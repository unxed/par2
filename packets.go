package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
)

var (
	TypeMain      = [16]byte{'P', 'A', 'R', ' ', '2', '\x00', 'M', 'a', 'i', 'n', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'}
	TypeFileDesc  = [16]byte{'P', 'A', 'R', ' ', '2', '\x00', 'F', 'i', 'l', 'e', 'D', 'e', 's', 'c', '\x00', '\x00'}
	TypeIFSC      = [16]byte{'P', 'A', 'R', ' ', '2', '\x00', 'I', 'F', 'S', 'C', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'}
	TypeRecvSlice = [16]byte{'P', 'A', 'R', ' ', '2', '\x00', 'R', 'e', 'c', 'v', 'S', 'l', 'i', 'c', '\x00', '\x00'}
	TypeCreator   = [16]byte{'P', 'A', 'R', ' ', '2', '\x00', 'C', 'r', 'e', 'a', 't', 'o', 'r', '\x00', '\x00'}
)

type PacketHeader struct {
	Magic         [8]byte
	Length        uint64
	PacketHash    [16]byte
	RecoverySetID [16]byte
	Type          [16]byte
}

func (h *PacketHeader) WriteTo(w io.Writer) error {
	copy(h.Magic[:], "PAR 2\x00PK")
	return binary.Write(w, binary.LittleEndian, h)
}

type MainPacket struct {
	SliceSize uint64
	NumFiles  uint32
	FileIDs   [][16]byte
}

func (p *MainPacket) Serialize(recoverySetID [16]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, p.SliceSize)
	binary.Write(buf, binary.LittleEndian, p.NumFiles)
	for _, id := range p.FileIDs {
		buf.Write(id[:])
	}
	body := buf.Bytes()
	packetHash := md5.Sum(body)
	hdr := PacketHeader{
		Length:        uint64(64 + len(body)),
		PacketHash:    packetHash,
		RecoverySetID: recoverySetID,
		Type:          TypeMain,
	}
	out := new(bytes.Buffer)
	hdr.WriteTo(out)
	out.Write(body)
	return out.Bytes(), nil
}

type FileDescPacket struct {
	FileID   [16]byte
	FileHash [16]byte
	Hash16k  [16]byte
	Length   uint64
	Name     string
}

func (p *FileDescPacket) Serialize(recoverySetID [16]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, p.FileID)
	binary.Write(buf, binary.LittleEndian, p.FileHash)
	binary.Write(buf, binary.LittleEndian, p.Hash16k)
	binary.Write(buf, binary.LittleEndian, p.Length)
	nameBytes := []byte(p.Name)
	buf.Write(nameBytes)
	padding := (4 - (len(nameBytes) % 4)) % 4
	if padding > 0 {
		buf.Write(make([]byte, padding))
	}
	body := buf.Bytes()
	packetHash := md5.Sum(body)
	hdr := PacketHeader{
		Length:        uint64(64 + len(body)),
		PacketHash:    packetHash,
		RecoverySetID: recoverySetID,
		Type:          TypeFileDesc,
	}
	out := new(bytes.Buffer)
	hdr.WriteTo(out)
	out.Write(body)
	return out.Bytes(), nil
}

type SliceChecksums struct {
	MD5   [16]byte
	CRC32 [4]byte
}

type IFSCPacket struct {
	FileID    [16]byte
	Checksums []SliceChecksums
}

func (p *IFSCPacket) Serialize(recoverySetID [16]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, p.FileID)
	for _, c := range p.Checksums {
		buf.Write(c.MD5[:])
		buf.Write(c.CRC32[:])
	}
	body := buf.Bytes()
	packetHash := md5.Sum(body)
	hdr := PacketHeader{
		Length:        uint64(64 + len(body)),
		PacketHash:    packetHash,
		RecoverySetID: recoverySetID,
		Type:          TypeIFSC,
	}
	out := new(bytes.Buffer)
	hdr.WriteTo(out)
	out.Write(body)
	return out.Bytes(), nil
}

type RecoverySlicePacket struct {
	Exponent uint32
	Data     []byte
}

func (p *RecoverySlicePacket) Serialize(recoverySetID [16]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, p.Exponent)
	buf.Write(p.Data)
	body := buf.Bytes()
	packetHash := md5.Sum(body)
	hdr := PacketHeader{
		Length:        uint64(64 + len(body)),
		PacketHash:    packetHash,
		RecoverySetID: recoverySetID,
		Type:          TypeRecvSlice,
	}
	out := new(bytes.Buffer)
	hdr.WriteTo(out)
	out.Write(body)
	return out.Bytes(), nil
}

type CreatorPacket struct {
	Creator string
}

func (p *CreatorPacket) Serialize(recoverySetID [16]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	creatorBytes := []byte(p.Creator)
	buf.Write(creatorBytes)
	padding := (4 - (len(creatorBytes) % 4)) % 4
	if padding > 0 {
		buf.Write(make([]byte, padding))
	}
	body := buf.Bytes()
	packetHash := md5.Sum(body)
	hdr := PacketHeader{
		Length:        uint64(64 + len(body)),
		PacketHash:    packetHash,
		RecoverySetID: recoverySetID,
		Type:          TypeCreator,
	}
	out := new(bytes.Buffer)
	hdr.WriteTo(out)
	out.Write(body)
	return out.Bytes(), nil
}