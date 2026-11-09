package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionHeadAfterRemovalAndRestart(t *testing.T) {
	root := t.TempDir()
	storage, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { storage.close() }()
	const bucket, key = "reports", "history"
	dir := filepath.Join(storage.dir, bucket)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	put := func(body string) object {
		t.Helper()
		r := httptest.NewRequest("PUT", "/reports/history", strings.NewReader(body))
		r.Header.Set("X-Amz-Content-Sha256", digest(body))
		obj, err := storage.put(bucket, key, r)
		if err != nil {
			t.Fatal(err)
		}
		return obj
	}
	check := func(id, contents string, deleted bool) {
		t.Helper()
		file, obj, err := storage.openVersion(dir, digest(key), "")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		body, err := io.ReadAll(io.NewSectionReader(file, 0, obj.Size))
		if err != nil || obj.VersionID != id || string(body) != contents || obj.DeleteMarker != deleted {
			t.Fatalf("current version = %s, %q, delete marker %v, error %v", obj.VersionID, body, obj.DeleteMarker, err)
		}
	}
	put("legacy")
	if err := writeMetadataFile(dir, versionConfig, []byte("Enabled")); err != nil {
		t.Fatal(err)
	}
	check("null", "legacy", false)
	first := put("first")
	second := put("second")
	check(second.VersionID, "second", false)
	marker, err := storage.removeVersion(dir, key, "", false)
	if err != nil {
		t.Fatal(err)
	}
	check(marker.VersionID, "", true)
	if _, err := storage.removeVersion(dir, key, marker.VersionID, false); err != nil {
		t.Fatal(err)
	}
	check(second.VersionID, "second", false)
	if _, err := storage.removeVersion(dir, key, second.VersionID, false); err != nil {
		t.Fatal(err)
	}
	check(first.VersionID, "first", false)

	// Recovery discards staging files left by a process that exited mid-upload.
	staged := filepath.Join(dir, ".upload-interrupted")
	if err := os.WriteFile(staged, []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	storage.close()
	reopened, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	storage = reopened
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("expected abandoned staging file to be removed, got %v", err)
	}
	check(first.VersionID, "first", false)
	if err := writeMetadataFile(dir, versionConfig, []byte("Suspended")); err != nil {
		t.Fatal(err)
	}
	put("new null")
	check("null", "new null", false)
	if _, err := storage.removeVersion(dir, key, "null", false); err != nil {
		t.Fatal(err)
	}
	check(first.VersionID, "first", false)
}

func BenchmarkVersionHead(b *testing.B) {
	storage, err := openStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer storage.close()
	dir := filepath.Join(storage.dir, "reports")
	name := digest("history")
	history := filepath.Join(dir, versionsPrefix+name)
	if err := os.MkdirAll(history, 0700); err != nil {
		b.Fatal(err)
	}
	if err := writeMetadataFile(dir, versionConfig, []byte("Enabled")); err != nil {
		b.Fatal(err)
	}
	const versions = 1000
	for sequence := 1; sequence <= versions; sequence++ {
		id := fmt.Sprintf("%032x", sequence)
		data, err := json.Marshal(object{Key: "history", VersionID: id, Sequence: int64(sequence)})
		if err != nil {
			b.Fatal(err)
		}
		data = binary.BigEndian.AppendUint32(data, uint32(len(data)))
		if err := os.WriteFile(filepath.Join(history, id), data, 0600); err != nil {
			b.Fatal(err)
		}
	}
	for _, test := range []struct {
		name string
		cold bool
	}{{"cold", true}, {"warm", false}} {
		b.Run(test.name, func(b *testing.B) {
			for b.Loop() {
				if test.cold {
					storage.clearVersionHeads()
				}
				file, obj, err := storage.openVersion(dir, name, "")
				if err != nil {
					b.Fatal(err)
				}
				file.Close()
				if obj.Sequence != versions {
					b.Fatalf("current sequence = %d", obj.Sequence)
				}
			}
		})
	}
}
