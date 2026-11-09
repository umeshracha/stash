package fsutil

import (
	"errors"
	"os"
	"path/filepath"
)

func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func WriteFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".upload-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.Write(data)
	if err := errors.Join(writeErr, tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	return SyncDir(dir)
}
