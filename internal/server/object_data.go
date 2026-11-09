package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"stash/internal/erasure"
	"strings"
)

type objectReader interface {
	io.ReaderAt
	io.Closer
}

func (s *store) objectData(file *os.File, obj object) (objectReader, error) {
	var data objectReader = file
	if obj.ErasureID != "" {
		file.Close()
		if s.erasure == nil {
			return nil, erasure.ErrQuorum
		}
		reader, err := s.erasure.OpenObject(obj.ErasureID, obj.payloadSize())
		if err != nil {
			return nil, err
		}
		data = reader
	}
	if obj.Encryption == nil {
		return data, nil
	}
	reader, err := s.encryption.Reader(data, obj.Key, obj.Size, obj.Encryption)
	if err != nil {
		data.Close()
		return nil, err
	}
	return reader, nil
}

func (s *store) commitData(file *os.File, dir, name string, obj *object) error {
	if s.erasure != nil && !obj.DeleteMarker && obj.Size > 0 {
		id, err := s.erasure.Encode(file, obj.payloadSize())
		if err != nil {
			return err
		}
		obj.ErasureID = id
		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	return commitObject(file, dir, name, *obj)
}

func (s *store) healAll(cleanup bool) error {
	if s.erasure == nil {
		return errors.New("healing requires an erasure configuration")
	}
	buckets, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var failed error
	referenced := make(map[string]bool)
	visit := func(bucket string, obj object) {
		if obj.ErasureID == "" || referenced[obj.ErasureID] {
			return
		}
		referenced[obj.ErasureID] = true
		repaired, err := s.erasure.Heal(obj.ErasureID, obj.payloadSize())
		if repaired > 0 {
			fmt.Printf("Repaired %d shards for %s version %s\n", repaired, bucket, obj.VersionID)
		}
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("%s shard set %s: %w", bucket, obj.ErasureID, err))
		}
	}
	for _, bucket := range buckets {
		if !bucket.IsDir() || !bucketName.MatchString(bucket.Name()) {
			continue
		}
		dir := filepath.Join(s.dir, bucket.Name())
		names, err := versionNames(dir)
		if err != nil {
			return err
		}
		for _, name := range names {
			versions, err := versionsFor(dir, name)
			if err != nil {
				return err
			}
			for _, version := range versions {
				visit(bucket.Name(), version.object)
			}
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			id, ok := strings.CutPrefix(entry.Name(), ".mp-")
			if !ok || !erasure.ValidID(id) {
				continue
			}
			stage := filepath.Join(dir, entry.Name())
			parts, err := os.ReadDir(stage)
			if err != nil {
				return err
			}
			for _, part := range parts {
				if !strings.HasPrefix(part.Name(), "part-") {
					continue
				}
				obj, err := metadataAt(filepath.Join(stage, part.Name()))
				if err != nil {
					return err
				}
				visit(bucket.Name(), obj)
			}
		}
	}
	if failed != nil || !cleanup {
		return failed
	}
	return s.erasure.RemoveUnreferenced(referenced)
}
