package par2

import (
    "encoding/binary"
    "crypto/md5"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unxed/par2/gf16"
)

func TestPAR2_FullRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "target_archive.bin")

	// 1. Генерируем тестовый файл размером 64 КБ с четко различимыми паттернами.
	// При размере файла в 64 КБ кодер автоматически выберет размер блока (Slice Size) в 16 КБ.
	// Это даст ровно 4 блока данных: блок 0, 1, 2 и 3.
	originalData := make([]byte, 64*1024)
	for i := range originalData {
		originalData[i] = byte('A' + (i/1024)%26)
	}
	if err := os.WriteFile(filePath, originalData, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// 2. Генерируем 50% избыточности (даст ровно 2 избыточных блока)
	parBytes, err := GeneratePAR2Data(filePath, 50)
	if err != nil {
		t.Fatalf("GeneratePAR2Data failed: %v", err)
	}

	// 3. Верифицируем структуру сгенерированных пакетов
	mainPkt, desc, ifsc, recvSlices, err := ParsePackets(parBytes)
	if err != nil {
		t.Fatalf("ParsePackets failed: %v", err)
	}

	if mainPkt == nil || desc == nil || ifsc == nil {
		t.Fatal("critical packets are missing from serialized par2 payload")
	}

	if mainPkt.SliceSize != 16*1024 {
		t.Errorf("expected slice size 16KB, got %d", mainPkt.SliceSize)
	}

	if len(ifsc.Checksums) != 4 {
		t.Errorf("expected 4 data blocks checksums, got %d", len(ifsc.Checksums))
	}

	if len(recvSlices) != 2 {
		t.Errorf("expected exactly 2 recovery blocks (50%% of 4), got %d", len(recvSlices))
	}

	// 4. Сценарий 1: Портим 1 блок данных (блок 1, смещение 16КБ)
	corruptedData := make([]byte, len(originalData))
	copy(corruptedData, originalData)
	for i := 0; i < 500; i++ {
		corruptedData[16*1024+i] = 0xAA // вносим "мусор" в блок 1
	}
	if err := os.WriteFile(filePath, corruptedData, 0644); err != nil {
		t.Fatal(err)
	}

	// Запускаем починку
	if err := RepairFile(filePath, parBytes); err != nil {
		t.Fatalf("RepairFile failed to restore 1 corrupted block: %v", err)
	}

	// Проверяем побитовое совпадение с оригиналом
	repairedData, _ := os.ReadFile(filePath)
	if !bytes.Equal(repairedData, originalData) {
		t.Error("Integrity check failed: 1 corrupted block was reconstructed incorrectly!")
	}

	// 5. Сценарий 2: Портим сразу 2 блока (блок 1 на 16КБ и блок 3 на 48КБ)
	copy(corruptedData, originalData)
	for i := 0; i < 500; i++ {
		corruptedData[16*1024+i] = 0xAA    // портим блок 1
		corruptedData[48*1024+i] = 0xBB    // портим блок 3
	}
	if err := os.WriteFile(filePath, corruptedData, 0644); err != nil {
		t.Fatal(err)
	}

	// Запускаем починку для двух блоков
	if err := RepairFile(filePath, parBytes); err != nil {
		t.Fatalf("RepairFile failed to restore 2 corrupted blocks: %v", err)
	}

	repairedData2, _ := os.ReadFile(filePath)
	if !bytes.Equal(repairedData2, originalData) {
		t.Error("Integrity check failed: 2 corrupted blocks were reconstructed incorrectly!")
	}

	// 6. Сценарий 3: Портим 3 блока (блок 0, 1 и 2). Лимит превышен.
	copy(corruptedData, originalData)
	for i := 0; i < 500; i++ {
		corruptedData[i] = 0x99            // портим блок 0
		corruptedData[16*1024+i] = 0xAA    // портим блок 1
		corruptedData[32*1024+i] = 0xBB    // портим блок 2
	}
	if err := os.WriteFile(filePath, corruptedData, 0644); err != nil {
		t.Fatal(err)
	}

	// Попытка починки должна завершиться ошибкой нехватки блоков избыточности
	err = RepairFile(filePath, parBytes)
	if err == nil {
		t.Error("expected RepairFile to fail when corrupted blocks count exceeds recovery blocks count, but it succeeded")
	} else if !strings.Contains(err.Error(), "not enough recovery slices") {
		t.Errorf("expected 'not enough recovery slices' error, got: %v", err)
	}
}

func TestGF16_MatrixSingular(t *testing.T) {
	// Матрица, заполненная нулями, является вырожденной (singular) и не имеет обратной.
	// Решатель должен вернуть ошибку.
	m := gf16.NewMatrix(2, 2)
	b := []uint16{1, 2}

	if err := m.Solve(b); err == nil {
		t.Error("expected error when solving singular matrix, got nil")
	}
}

func TestPAR2_TinyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "tiny.bin")

	// Файл размером всего 1 байт
	if err := os.WriteFile(filePath, []byte("A"), 0644); err != nil {
		t.Fatal(err)
	}

	parBytes, err := GeneratePAR2Data(filePath, 10)
	if err != nil {
		t.Fatalf("failed to generate PAR2 for 1-byte file: %v", err)
	}

	mainPkt, desc, ifsc, _, err := ParsePackets(parBytes)
	if err != nil {
		t.Fatalf("failed to parse packets for tiny file: %v", err)
	}

	if mainPkt.SliceSize != 16*1024 {
		t.Errorf("expected minimum slice size 16KB, got %d", mainPkt.SliceSize)
	}
	if len(ifsc.Checksums) != 1 {
		t.Errorf("expected 1 checksum block, got %d", len(ifsc.Checksums))
	}
	if desc.Length != 1 {
		t.Errorf("expected file length 1, got %d", desc.Length)
	}
}

func TestPAR2_CorruptPacketsTolerance(t *testing.T) {
	// 1. Тестируем поведение при обрыве потока посреди заголовка пакета
	truncatedData := []byte("PAR 2\x00PK") // Оборванный заголовок (меньше 64 байт)
	_, _, _, _, err := ParsePackets(truncatedData)
	if err == nil {
		t.Error("expected error when parsing truncated packet headers, got nil")
	}

	// 2. Тестируем поведение при повреждении тела пакета
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "dummy.bin")
	os.WriteFile(filePath, []byte("some dummy data for hashing"), 0644)

	parBytes, _ := GeneratePAR2Data(filePath, 10)

	// Намеренно портим один байт в теле первого пакета (на смещении 80, тело первого пакета занимает 64-95)
	corruptedBytes := make([]byte, len(parBytes))
	copy(corruptedBytes, parBytes)
	if len(corruptedBytes) > 80 {
		corruptedBytes[80] ^= 0xFF // Инвертируем биты строго в теле пакета
	}

	// Парсер не должен возвращать ошибку или паниковать,
	// он должен тихо отбросить поврежденный пакет по несовпадению MD5-хэша и продолжить работу.
	_, _, _, _, err = ParsePackets(corruptedBytes)
	if err != nil {
		t.Fatalf("ParsePackets failed to skip corrupted packet: %v", err)
	}
}
func TestPAR2_PaddedFileReconstruction(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "padded.bin")

	// 1. Создаем файл некратного размера (например, 50 000 байт).
	// При блоке 16 КБ (16384 байта) это даст 3 полных блока и 1 неполный (padded) блок размером 848 байт.
	originalSize := int64(50000)
	originalData := make([]byte, originalSize)
	for i := range originalData {
		originalData[i] = byte('X' + (i/1024)%3)
	}
	if err := os.WriteFile(filePath, originalData, 0644); err != nil {
		t.Fatal(err)
	}

	parBytes, err := GeneratePAR2Data(filePath, 30)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Портим неполный (последний) блок файла на диске
	corruptedData := make([]byte, originalSize)
	copy(corruptedData, originalData)
	corruptedData[49900] = 0x00 // Портим байт в хвосте

	if err := os.WriteFile(filePath, corruptedData, 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Запускаем восстановление
	if err := RepairFile(filePath, parBytes); err != nil {
		t.Fatalf("RepairFile failed to restore padded file: %v", err)
	}

	// 4. Сверх-параноидальная проверка:
	// Файл должен восстановиться побитово, а его размер на диске должен остаться СТРОГО 50 000 байт.
	// Округление блока до 16 КБ не должно было раздуть файл!
	fi, err := os.Stat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != originalSize {
		t.Errorf("Padding Bloat detected! Expected file size %d, got %d", originalSize, fi.Size())
	}

	repairedData, _ := os.ReadFile(filePath)
	if !bytes.Equal(repairedData, originalData) {
		t.Error("Reconstructed padded block data is corrupted")
	}
}

func TestPAR2_CryptographicVerificationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "verif_fail.bin")

	originalData := make([]byte, 32*1024) // 32KB
	for i := range originalData {
		originalData[i] = byte('Z')
	}
	os.WriteFile(filePath, originalData, 0644)

	parBytes, _ := GeneratePAR2Data(filePath, 50)

	// Намеренно портим исходный файл
	corruptedData := make([]byte, len(originalData))
	copy(corruptedData, originalData)
	corruptedData[5] = 0x11 // портим блок 0
	os.WriteFile(filePath, corruptedData, 0644)

	// Намеренно портим тело избыточного пакета восстановления в parBytes
	corruptedPar := make([]byte, len(parBytes))
	copy(corruptedPar, parBytes)

	idx := bytes.Index(corruptedPar, TypeRecvSlice[:])
	if idx != -1 {
		headerStart := idx - 48
		length := binary.LittleEndian.Uint64(corruptedPar[headerStart+8 : headerStart+16])
		bodySize := length - 64
		bodyStart := headerStart + 64

		// 1. Вносим искажение в данные восстановления (смещение 10 от начала тела пакета)
		corruptedPar[bodyStart+10] ^= 0x55

		// 2. Пересчитываем MD5-хэш измененного тела
		newHash := md5.Sum(corruptedPar[bodyStart : bodyStart+int(bodySize)])

		// 3. Перезаписываем PacketHash в заголовке пакета на смещении 16 (размер поля 16 байт)
		copy(corruptedPar[headerStart+16 : headerStart+32], newHash[:])
	}

	// Восстановление должно завершиться ошибкой верификации MD5,
	// предотвращая запись битых данных Гаусса на диск!
	err := RepairFile(filePath, corruptedPar)
	if err == nil {
		t.Error("expected RepairFile to fail with cryptographic verification error, but it wrote corrupted data to disk")
	} else if !strings.Contains(err.Error(), "cryptographic verification failed") {
		t.Errorf("expected 'cryptographic verification failed' error, got: %v", err)
	}
}
