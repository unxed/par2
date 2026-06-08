package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"github.com/unxed/par2/gf16"
)

func addMulBlock(dst, src []byte, factor uint16) {
	if factor == 0 {
		return
	}
	for i := 0; i < len(src); i += 2 {
		val := binary.LittleEndian.Uint16(src[i : i+2])
		prod := gf16.Mul(val, factor)
		orig := binary.LittleEndian.Uint16(dst[i : i+2])
		binary.LittleEndian.PutUint16(dst[i : i+2], orig^prod)
	}
}

func GeneratePAR2Data(filename string, percentage int) ([]byte, error) {
	if percentage <= 0 {
		return nil, nil
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileLen := fi.Size()

	var sliceSize uint64 = 256 * 1024
	if fileLen < int64(sliceSize) {
		sliceSize = 16 * 1024
	}
	numSlices := (fileLen + int64(sliceSize) - 1) / int64(sliceSize)

	slices := make([][]byte, numSlices)
	checksums := make([]SliceChecksums, numSlices)

	fullHasher := md5.New()
	hash16kHasher := md5.New()

	for i := int64(0); i < numSlices; i++ {
		buf := make([]byte, sliceSize)
		n, _ := io.ReadFull(f, buf)
		if n > 0 {
			slices[i] = buf
			fullHasher.Write(buf[:n])
			if i == 0 {
				len16k := n
				if len16k > 16384 {
					len16k = 16384
				}
				hash16kHasher.Write(buf[:len16k])
			}

			sliceMD5 := md5.Sum(buf)
			sliceCRC32 := crc32.ChecksumIEEE(buf)

			checksums[i] = SliceChecksums{
				MD5: sliceMD5,
			}
			binary.LittleEndian.PutUint32(checksums[i].CRC32[:], sliceCRC32)
		}
	}

	var fileHash [16]byte
	var hash16k [16]byte
	copy(fileHash[:], fullHasher.Sum(nil))
	copy(hash16k[:], hash16kHasher.Sum(nil))

	rawName := []byte(filepath.Base(filename))
	padding := (4 - (len(rawName) % 4)) % 4

	descBuf := new(bytes.Buffer)
	descBuf.Write(make([]byte, 16))
	descBuf.Write(fileHash[:])
	descBuf.Write(hash16k[:])
	binary.Write(descBuf, binary.LittleEndian, uint64(fileLen))
	descBuf.Write(rawName)
	if padding > 0 {
		descBuf.Write(make([]byte, padding))
	}

	fileID := md5.Sum(descBuf.Bytes()[16:])
	recoverySetID := md5.Sum(fileID[:])

	numRecoverySlices := (numSlices * int64(percentage)) / 100
	if numRecoverySlices == 0 {
		numRecoverySlices = 1
	}

	recoverySlices := make([][]byte, numRecoverySlices)
	for i := range recoverySlices {
		recoverySlices[i] = make([]byte, sliceSize)
	}

	for i := uint32(0); i < uint32(numRecoverySlices); i++ {
		for j := uint32(0); j < uint32(numSlices); j++ {
			exponent := (i * j) % 65535
			factor := gf16.Pow(2, int(exponent))
			addMulBlock(recoverySlices[i], slices[j], factor)
		}
	}

	out := new(bytes.Buffer)

	creator := CreatorPacket{Creator: "zipper pure-go recovery engine"}
	b, _ := creator.Serialize(recoverySetID)
	out.Write(b)

	mainPkt := MainPacket{
		SliceSize: sliceSize,
		NumFiles:  1,
		FileIDs:   [][16]byte{fileID},
	}
	b, _ = mainPkt.Serialize(recoverySetID)
	out.Write(b)

	fileDesc := FileDescPacket{
		FileID:   fileID,
		FileHash: fileHash,
		Hash16k:  hash16k,
		Length:   uint64(fileLen),
		Name:     filepath.Base(filename),
	}
	b, _ = fileDesc.Serialize(recoverySetID)
	out.Write(b)

	ifsc := IFSCPacket{
		FileID:    fileID,
		Checksums: checksums,
	}
	b, _ = ifsc.Serialize(recoverySetID)
	out.Write(b)

	for i := uint32(0); i < uint32(numRecoverySlices); i++ {
		recSlice := RecoverySlicePacket{
			Exponent: i,
			Data:     recoverySlices[i],
		}
		b, _ = recSlice.Serialize(recoverySetID)
		out.Write(b)
	}

	return out.Bytes(), nil
}