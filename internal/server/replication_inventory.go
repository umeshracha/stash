package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
)

const maxInventoryRecord = 4 * maxMetadata

func (s *server) serveReplicaInventory(w http.ResponseWriter, r *http.Request, dir string) {
	file, err := os.CreateTemp(s.store.dir, ".inventory-")
	if err != nil {
		http.Error(w, "inventory unavailable", 503)
		return
	}
	defer file.Close()
	// The open descriptor remains readable while the process owns the snapshot.
	if err := os.Remove(file.Name()); err != nil {
		http.Error(w, "inventory unavailable", 503)
		return
	}
	s.store.mu.Lock()
	err = writeReplicaInventory(r.Context(), file, dir)
	s.store.mu.Unlock()
	if err != nil {
		http.Error(w, "inventory unavailable", 503)
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "inventory unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	io.Copy(w, file)
}

func writeReplicaInventory(ctx context.Context, w io.Writer, dir string) error {
	if err := checkReplicaCheckpoint(dir); err != nil {
		return err
	}
	header, err := inventoryHeader(dir)
	if err != nil {
		return err
	}
	if header.Status != "Enabled" && header.Status != "Suspended" {
		return errors.New("versioned bucket unavailable")
	}
	buffer := bufio.NewWriter(w)
	encoder := json.NewEncoder(buffer)
	if err := encoder.Encode(header); err != nil {
		return err
	}
	if err := walkInventory(dir, func(obj object) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return encoder.Encode(obj)
	}); err != nil {
		return err
	}
	if err := encoder.Encode(nil); err != nil {
		return err
	}
	return buffer.Flush()
}

func readReplicaInventory(r io.Reader, collect bool) (replicaManifest, string, error) {
	var manifest replicaManifest
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(r, hash))
	scanner.Buffer(make([]byte, 4096), maxInventoryRecord)
	invalid := errors.New("invalid or incomplete replication inventory")
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &manifest) != nil || len(manifest.Versions) != 0 ||
		manifest.Status != "Enabled" && manifest.Status != "Suspended" ||
		manifest.Lock != nil && (manifest.Status != "Enabled" || !validLockConfig(*manifest.Lock)) {
		return replicaManifest{}, "", invalid
	}
	for scanner.Scan() {
		if scanner.Text() == "null" {
			if scanner.Scan() || scanner.Err() != nil {
				return replicaManifest{}, "", invalid
			}
			return manifest, hex.EncodeToString(hash.Sum(nil)), nil
		}
		if collect {
			var obj object
			if json.Unmarshal(scanner.Bytes(), &obj) != nil {
				return replicaManifest{}, "", invalid
			}
			manifest.Versions = append(manifest.Versions, obj)
		}
	}
	return replicaManifest{}, "", invalid
}
