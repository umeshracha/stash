package main

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedObjectRoundTripAndCorruption(t *testing.T) {
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.encryption = &encryptionKeys{active: "first", keys: map[string][]byte{"first": bytes.Repeat([]byte{7}, 32)}}
	dir := filepath.Join(s.dir, "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("private payload marker"), 25000)
	request := httptest.NewRequest("PUT", "/", bytes.NewReader(data))
	request.Header.Set("X-Amz-Content-Sha256", digest(string(data)))
	obj, err := s.put("reports", "example", request)
	if err != nil || obj.Encryption == nil {
		t.Fatalf("encrypted write failed: %v", err)
	}
	path := filepath.Join(dir, digest("example"))
	stored, err := os.ReadFile(path)
	if err != nil || bytes.Contains(stored, []byte("private payload marker")) {
		t.Fatalf("plaintext was found in the stored object: %v", err)
	}
	read := func(offset int64, size int) ([]byte, error) {
		file, meta, err := openObjectFile(path)
		if err != nil {
			return nil, err
		}
		reader, err := s.objectData(file, meta)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(io.NewSectionReader(reader, offset, int64(size)))
	}
	start := encryptionBlock - 20
	got, err := read(int64(start), 40)
	if err != nil || !bytes.Equal(got, data[start:start+40]) {
		t.Fatalf("cross-chunk range read failed: %v", err)
	}
	stored[encryptionBlock+encryptionTagSize+12] ^= 0x80
	if err := os.WriteFile(path, stored, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = read(int64(encryptionBlock), 100)
	if !errors.Is(err, errCiphertext) || len(got) != 0 {
		t.Fatalf("corrupted chunk leaked data or returned the wrong error: %d bytes, %v", len(got), err)
	}
}
