package par2

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	gopar "github.com/akalin/gopar/par2"
	gonzbee "github.com/danielmorsing/gonzbee/par2"
)

func BenchmarkPAR2_Create_Comparison(b *testing.B) {
	tmpDir := b.TempDir()
	dataPath := filepath.Join(tmpDir, "data.bin")

	// 1MB data file
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(dataPath, data, 0644)

	b.Run("unxed/par2", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := GeneratePAR2Data(dataPath, 10)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("akalin/gopar", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			parPath := filepath.Join(tmpDir, fmt.Sprintf("gopar_%d.par2", i))
			err := gopar.Create(parPath, []string{dataPath}, gopar.CreateOptions{
				SliceByteCount:  256 * 1024,
				NumParityShards: 1, // 10% of 10 blocks is 1 block
			})
			if err != nil {
				b.Fatal(err)
			}
			os.Remove(parPath)
		}
	})
}

func BenchmarkPAR2_Repair_Comparison(b *testing.B) {
	tmpDir := b.TempDir()
	dataPath := filepath.Join(tmpDir, "data.bin")

	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(dataPath, data, 0644)

	// Generate 10% recovery record
	parBytes, _ := GeneratePAR2Data(dataPath, 10)

	b.Run("unxed/par2", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Corrupt 1 byte
			os.WriteFile(dataPath, append([]byte{0x00}, data[1:]...), 0644)
			err := RepairFile(dataPath, parBytes)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	goparPath := filepath.Join(tmpDir, "gopar.par2")
	gopar.Create(goparPath, []string{dataPath}, gopar.CreateOptions{
		SliceByteCount:  256 * 1024,
		NumParityShards: 1,
	})

	b.Run("akalin/gopar", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Corrupt 1 byte
			os.WriteFile(dataPath, append([]byte{0x00}, data[1:]...), 0644)
			_, err := gopar.Repair(goparPath, gopar.RepairOptions{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPAR2_Verify_Comparison(b *testing.B) {
	tmpDir := b.TempDir()
	dataPath := filepath.Join(tmpDir, "data.bin")

	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(dataPath, data, 0644)

	goparPath := filepath.Join(tmpDir, "gopar_verify.par2")
	gopar.Create(goparPath, []string{dataPath}, gopar.CreateOptions{
		SliceByteCount:  256 * 1024,
		NumParityShards: 1,
	})

	unxedParBytes, _ := GeneratePAR2Data(dataPath, 10)

	b.Run("unxed/par2", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f, err := os.Open(dataPath)
			if err != nil {
				b.Fatal(err)
			}
			err = RepairTargetData(f, unxedParBytes)
			f.Close()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("akalin/gopar", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := gopar.Verify(goparPath, gopar.VerifyOptions{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("danielmorsing/gonzbee", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f, err := os.Open(goparPath)
			if err != nil {
				b.Fatal(err)
			}
			fset := gonzbee.NewFileset(f)
			f.Close()
			_, _ = fset.Verify([]string{dataPath})
		}
	})
}