package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/unxed/par2/gf16"
)

func addMulBlock(dst, src []byte, factor uint16) {
	if factor == 0 {
		return
	}

	limit := len(src) / 2
	src16 := *(*[]uint16)(unsafe.Pointer(&src))
	dst16 := *(*[]uint16)(unsafe.Pointer(&dst))

	src16 = src16[:limit]
	dst16 = dst16[:limit]

	if factor == 1 {
		for i := 0; i < limit; i++ {
			dst16[i] ^= src16[i]
		}
		return
	}

	logFactor := int(gf16.GfLog[factor])
	for i := 0; i < limit; i++ {
		val := src16[i]
		if val == 0 {
			continue
		}
		logSum := int(gf16.GfLog[val]) + logFactor
		if logSum >= 65535 {
			logSum -= 65535
		}
		dst16[i] ^= gf16.GfExp[logSum]
	}
}

func GeneratePAR2Data(filename string, percentage int) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return GeneratePAR2Stream(f, fi.Size(), filepath.Base(filename), percentage)
}

// GeneratePAR2Stream генерирует пакеты восстановления, читая данные из абстрактного потока
func GeneratePAR2Stream(r io.Reader, fileLen int64, baseName string, percentage int) ([]byte, error) {
	if percentage <= 0 {
		return nil, nil
	}

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
		n, _ := io.ReadFull(r, buf)
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

	rawName := []byte(baseName)
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
		Name:     baseName,
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