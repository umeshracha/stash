package server

import (
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedOverwritePreservesObject(t *testing.T) {
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	dir := filepath.Join(store.dir, "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	const key = "../monthly report"
	put := func(body, checksum string) error {
		r := httptest.NewRequest("PUT", "/reports/unused", strings.NewReader(body))
		r.Header.Set("X-Amz-Content-Sha256", checksum)
		_, err := store.put("reports", key, r)
		return err
	}
	if err := put("original", digest("original")); err != nil {
		t.Fatal(err)
	}
	if err := put("replacement", digest("different")); !errors.Is(err, errChecksum) {
		t.Fatalf("expected checksum error, got %v", err)
	}
	file, err := os.Open(filepath.Join(dir, digest(key)))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	metadata, err := readMetadata(file)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.NewSectionReader(file, 0, metadata.Size))
	if err != nil || string(body) != "original" || metadata.Key != key {
		t.Fatalf("unexpected stored object %q, %q, %v", metadata.Key, body, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one committed file, got %d, %v", len(entries), err)
	}
}
