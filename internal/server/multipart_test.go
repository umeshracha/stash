package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverUploadsAfterCommit(t *testing.T) {
	root := t.TempDir()
	store, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	bucket := filepath.Join(store.dir, "reports")
	if err := os.Mkdir(bucket, 0700); err != nil {
		store.close()
		t.Fatal(err)
	}
	completedID := strings.Repeat("a", 32)
	activeID := strings.Repeat("b", 32)
	const key = "report.txt"
	for _, id := range []string{completedID, activeID} {
		stage := filepath.Join(bucket, ".mp-"+id)
		if err := os.Mkdir(stage, 0700); err != nil {
			store.close()
			t.Fatal(err)
		}
		manifest, err := json.Marshal(uploadInfo{Key: key, Headers: http.Header{}})
		if err != nil {
			store.close()
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, "upload.json"), manifest, 0600); err != nil {
			store.close()
			t.Fatal(err)
		}
	}
	file, err := os.CreateTemp(bucket, ".upload-")
	if err != nil {
		store.close()
		t.Fatal(err)
	}
	if err := commitObject(file, bucket, digest(key), object{Key: key, UploadID: completedID}); err != nil {
		file.Close()
		store.close()
		t.Fatal(err)
	}
	store.close()

	store, err = openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := os.Stat(filepath.Join(bucket, ".mp-"+completedID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed upload should be cleaned up: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bucket, ".mp-"+activeID, "upload.json")); err != nil {
		t.Fatalf("incomplete upload should survive: %v", err)
	}
	obj, err := metadataAt(filepath.Join(bucket, digest(key)))
	if err != nil || obj.UploadID != completedID {
		t.Fatalf("committed object should survive: %v, %v", obj, err)
	}
}
