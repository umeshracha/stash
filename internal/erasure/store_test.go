package erasure

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestErasureReadAndHealAcrossDriveFailures(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	drives := make([]string, 4)
	for i := range drives {
		drives[i] = filepath.Join(root, string(rune('a'+i)))
		if err := os.Mkdir(drives[i], 0700); err != nil {
			t.Fatal(err)
		}
	}
	ec, err := Open(root, &Config{Drives: drives, Parity: 2})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("stripe boundary payload"), 43000)
	id, err := ec.Encode(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(payload))
	expected, err := os.ReadFile(ec.shardPath(1, id))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ec.shardPath(0, id)); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(expected)
	corrupt[400] ^= 1
	if err := os.WriteFile(ec.shardPath(1, id), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := ec.OpenObject(id, size)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(reader, 0, size))
	reader.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("reconstruction failed, read %d bytes: %v", len(got), err)
	}
	repaired, err := ec.Heal(id, size)
	if err != nil || repaired != 2 {
		t.Fatalf("expected two repaired shards, got %d: %v", repaired, err)
	}
	actual, err := os.ReadFile(ec.shardPath(1, id))
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("healed shard differs from original: %v", err)
	}

	for _, path := range drives[:2] {
		if err := os.Rename(path, path+"-offline"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ec.Encode(bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, ErrQuorum) {
		t.Fatalf("write below quorum returned %v", err)
	}
}

func TestErasureReplacementAndSweepAreScopedToLayout(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	drives := []string{filepath.Join(root, "one"), filepath.Join(root, "two"), filepath.Join(root, "three")}
	for _, drive := range drives {
		if err := os.Mkdir(drive, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ec, err := Open(root, &Config{Drives: drives, Parity: 1})
	if err != nil {
		t.Fatal(err)
	}
	id, err := ec.Encode(bytes.NewReader([]byte("test")), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(drives[0], drives[0]+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(drives[0], 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ec.drives[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected shard namespace on the replacement drive: %v", err)
	}
	if err := ec.InitializeDrive(0); err != nil {
		t.Fatal(err)
	}
	repaired, err := ec.Heal(id, 4)
	if err != nil || repaired != 1 {
		t.Fatalf("expected one repaired shard, got %d: %v", repaired, err)
	}
	unrelated := filepath.Join(drives[0], id+".shard")
	if err := os.WriteFile(unrelated, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ec.RemoveUnreferenced(map[string]bool{id: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ec.shardPath(0, id)); err != nil {
		t.Fatalf("referenced shard removed: %v", err)
	}
	if err := ec.RemoveUnreferenced(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ec.shardPath(0, id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unreferenced shard was retained: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("file outside the layout was removed: %v", err)
	}
}
