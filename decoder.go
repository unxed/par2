package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/unxed/par2/gf16"
)

func ParsePackets(data []byte) (*MainPacket, *FileDescPacket, *IFSCPacket, []*RecoverySlicePacket, error) {
	r := bytes.NewReader(data)
	var mainPkt *MainPacket
	var fileDesc *FileDescPacket
	var ifsc *IFSCPacket
	var recvSlices []*RecoverySlicePacket

	for {
		pos, _ := r.Seek(0, io.SeekCurrent)
		var hdr PacketHeader
		err := binary.Read(r, binary.LittleEndian, &hdr)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to read packet header: %w", err)
		}

		magicStr := string(hdr.Magic[:])
		if magicStr != "PAR 2\x00PK" {
			return nil, nil, nil, nil, fmt.Errorf("invalid PAR2 magic signature (got %q, hex: %x) at offset %d", magicStr, hdr.Magic[:], pos)
		}

		bodyLen := hdr.Length - 64
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("truncated packet body")
		}

		if md5.Sum(body) != hdr.PacketHash {
			continue // Skip corrupted packets
		}

		br := bytes.NewReader(body)

		switch hdr.Type {
		case TypeMain:
			mainPkt = &MainPacket{}
			binary.Read(br, binary.LittleEndian, &mainPkt.SliceSize)
			binary.Read(br, binary.LittleEndian, &mainPkt.NumFiles)
			numIDs := (bodyLen - 12) / 16
			mainPkt.FileIDs = make([][16]byte, numIDs)
			for i := range mainPkt.FileIDs {
				binary.Read(br, binary.LittleEndian, &mainPkt.FileIDs[i])
			}

		case TypeFileDesc:
			fileDesc = &FileDescPacket{}
			binary.Read(br, binary.LittleEndian, &fileDesc.FileID)
			binary.Read(br, binary.LittleEndian, &fileDesc.FileHash)
			binary.Read(br, binary.LittleEndian, &fileDesc.Hash16k)
			binary.Read(br, binary.LittleEndian, &fileDesc.Length)
			nameBytes := make([]byte, br.Len())
			binary.Read(br, binary.LittleEndian, nameBytes)
			fileDesc.Name = string(bytes.TrimRight(nameBytes, "\x00"))

		case TypeIFSC:
			ifsc = &IFSCPacket{}
			binary.Read(br, binary.LittleEndian, &ifsc.FileID)
			numChecksums := (bodyLen - 16) / 20
			ifsc.Checksums = make([]SliceChecksums, numChecksums)
			for i := range ifsc.Checksums {
				binary.Read(br, binary.LittleEndian, &ifsc.Checksums[i].MD5)
				binary.Read(br, binary.LittleEndian, &ifsc.Checksums[i].CRC32)
			}

		case TypeRecvSlice:
			slice := &RecoverySlicePacket{}
			binary.Read(br, binary.LittleEndian, &slice.Exponent)
			slice.Data = make([]byte, br.Len())
			binary.Read(br, binary.LittleEndian, slice.Data)
			recvSlices = append(recvSlices, slice)
		}
	}

	return mainPkt, fileDesc, ifsc, recvSlices, nil
}

// RepairTarget абстрагирует физический файл (или несколько файлов многотомного архива)
// для выполнения операций чтения и записи блоков восстановления на месте.
type RepairTarget interface {
	io.ReaderAt
	io.WriterAt
}

func RepairFile(targetFile string, par2Data []byte) error {
	f, err := os.OpenFile(targetFile, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := RepairTargetData(f, par2Data); err != nil {
		return err
	}

	_, fileDesc, _, _, _ := ParsePackets(par2Data)
	return f.Truncate(int64(fileDesc.Length))
}

// RepairTargetData выполняет In-Place восстановление Рида-Соломона над абстрактной мишенью
func RepairTargetData(target RepairTarget, par2Data []byte) error {
	mainPkt, fileDesc, ifsc, recvSlices, err := ParsePackets(par2Data)
	if err != nil {
		return err
	}
	if ifsc == nil || mainPkt == nil || fileDesc == nil {
		return fmt.Errorf("missing critical metadata packets (IFSC/Main/FileDesc)")
	}

	sliceSize := mainPkt.SliceSize
	numSlices := len(ifsc.Checksums)

	var missingSlices []int
	survivingSlices := make(map[int][]byte)

	for i := 0; i < numSlices; i++ {
		buf := make([]byte, sliceSize)
		n, _ := target.ReadAt(buf, int64(i)*int64(sliceSize))
		_ = n

		actualMD5 := md5.Sum(buf)
		if actualMD5 != ifsc.Checksums[i].MD5 {
			missingSlices = append(missingSlices, i)
		} else {
			survivingSlices[i] = buf
		}
	}

	if len(missingSlices) == 0 {
		return nil
	}

	if len(missingSlices) > len(recvSlices) {
		return fmt.Errorf("not enough recovery slices to repair: need %d, have %d", len(missingSlices), len(recvSlices))
	}

	k := len(missingSlices)
	matrix := gf16.NewMatrix(k, k)
	bVectors := make([][]byte, k)
	for i := range bVectors {
		bVectors[i] = make([]byte, sliceSize)
	}

	for p := 0; p < k; p++ {
		rP := recvSlices[p].Exponent
		copy(bVectors[p], recvSlices[p].Data)

		for idx, dataSlice := range survivingSlices {
			exponent := (rP * uint32(idx)) % 65535
			factor := gf16.Pow(2, int(exponent))
			addMulBlock(bVectors[p], dataSlice, factor)
		}

		for q := 0; q < k; q++ {
			idxMissing := missingSlices[q]
			exponent := (rP * uint32(idxMissing)) % 65535
			factor := gf16.Pow(2, int(exponent))
			matrix.Set(p, q, factor)
		}
	}

	for offset := uint64(0); offset < sliceSize; offset += 2 {
		b := make([]uint16, k)
		for p := 0; p < k; p++ {
			b[p] = binary.LittleEndian.Uint16(bVectors[p][offset : offset+2])
		}

		matrixCopy := gf16.NewMatrix(k, k)
		copy(matrixCopy.Data, matrix.Data)
		if err := matrixCopy.Solve(b); err != nil {
			return fmt.Errorf("reconstruction matrix is singular: %w", err)
		}

		for q := 0; q < k; q++ {
			binary.LittleEndian.PutUint16(bVectors[q][offset:offset+2], b[q])
		}
	}

	// 4. Параноидальная проверка (Post-Repair Verification):
	// Сверяем MD5 каждого восстановленного в памяти блока с оригинальным IFSC хэшем
	// ДО записи на физический диск.
	for q := 0; q < k; q++ {
		idxMissing := missingSlices[q]
		recalculatedMD5 := md5.Sum(bVectors[q])
		if recalculatedMD5 != ifsc.Checksums[idxMissing].MD5 {
			return fmt.Errorf("cryptographic verification failed: reconstructed block %d is corrupted or mathematically inconsistent", idxMissing)
		}
	}

	// 5. Записываем восстановленные блоки обратно в файл на диске
	for q := 0; q < k; q++ {
		idxMissing := missingSlices[q]
		if _, err := target.WriteAt(bVectors[q], int64(idxMissing)*int64(sliceSize)); err != nil {
			return fmt.Errorf("failed to write repaired block %d back to disk: %w", idxMissing, err)
		}
	}

	return nil
}
