package par2

import (
	"bytes"
	"testing"
)

// memTarget is a file held in memory, as RepairTargetData sees one.
type memTarget struct{ data []byte }

func (m *memTarget) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, nil
	}
	return copy(p, m.data[off:]), nil
}

func (m *memTarget) WriteAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, nil
	}
	return copy(m.data[off:], p), nil
}

// TestRepairTargetData_ShortLastSlice: a file whose last slice is short can
// lose as many slices as there are recovery slices and still be repaired. The
// verification pass read each slice into one reused buffer, so the short last
// slice was checked with the previous slice's bytes behind it, never matched,
// and was counted as damaged on top of the slices that were.
func TestRepairTargetData_ShortLastSlice(t *testing.T) {
	orig := make([]byte, 700*1024+123)
	for i := range orig {
		orig[i] = byte(i*31 + i/7)
	}
	parData, err := GeneratePAR2Stream(bytes.NewReader(orig), int64(len(orig)), "short.bin", 10)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	mainPkt, _, ifsc, recv, err := ParsePackets(parData)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	slice := int(mainPkt.SliceSize)
	numSlices := len(ifsc.Checksums)
	if len(orig)%slice == 0 || numSlices < len(recv)+2 || len(recv) == 0 {
		t.Fatalf("the fixture needs a short last slice and more slices than recovery slices: %d bytes, slice %d, %d slices, %d recovery", len(orig), slice, numSlices, len(recv))
	}

	damaged := append([]byte(nil), orig...)
	for s := 0; s < len(recv); s++ {
		damaged[s*slice+5] ^= 0xff
	}
	target := &memTarget{data: damaged}
	if err := RepairTargetData(target, parData); err != nil {
		t.Fatalf("repairing %d damaged slices with %d recovery slices: %v", len(recv), len(recv), err)
	}
	if !bytes.Equal(target.data, orig) {
		t.Fatal("the repaired data differs from the original")
	}
}
