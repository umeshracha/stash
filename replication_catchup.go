package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type replicaHTTPError int

func (status replicaHTTPError) Error() string {
	return fmt.Sprintf("replication source returned HTTP %d", status)
}

func (service *replication) delta(ctx context.Context, source replicaSource, cursor string) (replicaDelta, error) {
	var delta replicaDelta
	response, err := service.fetch(ctx, source, "changes", url.Values{"cursor": {cursor}})
	if err != nil {
		return delta, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifest+1))
	if err != nil || len(body) > maxManifest || json.Unmarshal(body, &delta) != nil ||
		delta.Cursor == "" || len(delta.Cursor) > 64 || len(delta.Changes) > replicaFeedCapacity ||
		delta.Status != "Enabled" && delta.Status != "Suspended" ||
		delta.Lock != nil && (delta.Status != "Enabled" || !validLockConfig(*delta.Lock)) {
		return delta, errors.New("invalid replication change feed")
	}
	return delta, nil
}

func (service *replication) catchUp(ctx context.Context, bucket string, source replicaSource, state replicaStatus) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	dir := filepath.Join(service.store.dir, bucket)
	delta, err := service.delta(ctx, source, state.Cursor)
	if err != nil && !errors.Is(err, replicaHTTPError(http.StatusNotFound)) {
		return "", "", 0, err
	}
	if err == nil && state.Cursor != "" && !delta.Reset && checkReplicaCheckpoint(dir) == nil {
		count, err := service.applyDelta(ctx, source, dir, delta, state.Versions)
		return delta.Cursor, delta.Cursor, count, err
	}
	// Keep the cursor observed before backfill. Replaying overlapping changes
	// afterward is safe and covers writes made while the baseline was installed.
	revision, count, err := service.reconcile(ctx, bucket, source)
	return revision, delta.Cursor, count, err
}

func (service *replication) applyDelta(ctx context.Context, source replicaSource, dir string, delta replicaDelta, count int) (int, error) {
	status, err := versionStatus(dir)
	if err != nil {
		return 0, err
	}
	lock, err := readLockConfig(dir)
	if err != nil {
		return 0, err
	}
	if lock != nil && delta.Lock == nil {
		return 0, errors.New("source object lock configuration disappeared")
	}
	lockChanged := !reflect.DeepEqual(lock, delta.Lock)
	if len(delta.Changes) == 0 && status == delta.Status && !lockChanged {
		return count, nil
	}

	var staged []replicaTransfer
	defer func() {
		for _, item := range staged {
			os.Remove(item.temp)
		}
	}()
	var removed []string
	seen := make(map[replicaKey]bool)
	for _, change := range delta.Changes {
		key := change.Key
		if seen[key] || !validKey(key.Key) || !validVersion(key.Version) {
			return 0, errors.New("invalid or duplicate replication change")
		}
		seen[key] = true
		path := replicaVersionPath(dir, key.Key, key.Version)
		current, err := metadataAt(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		exists := err == nil
		if change.Object == nil {
			if exists {
				removed = append(removed, path)
				count--
			}
			continue
		}
		obj := *change.Object
		if obj.Key != key.Key || obj.VersionID != key.Version || obj.Size < 0 || obj.Size > maxMultipartSize ||
			obj.DeleteMarker && obj.Size != 0 || obj.VersionID != "null" && obj.Sequence <= 0 ||
			obj.Encryption != nil || obj.ErasureID != "" {
			return 0, errors.New("invalid replication version")
		}
		if exists && objectRevision(current) == objectRevision(obj) &&
			(obj.SHA256 == "" || current.SHA256 == obj.SHA256) && (current.SHA256 != "" || current.DeleteMarker) {
			continue
		}
		if !exists {
			count++
		}
		item, err := service.transfer(ctx, source, dir, obj)
		if err != nil {
			return 0, err
		}
		staged = append(staged, item)
	}
	latest, err := service.delta(ctx, source, delta.Cursor)
	if err != nil {
		return 0, err
	}
	// New writes after the staged checkpoint are handled on the next poll.
	if latest.Reset {
		return 0, errors.New("replication checkpoint expired during transfer; retrying")
	}
	if len(staged) == 0 && len(removed) == 0 && status == delta.Status && !lockChanged {
		return count, nil
	}

	service.store.mu.Lock()
	defer service.store.mu.Unlock()
	service.store.clearVersionHeads()
	if err := writeMetadataFile(dir, replicaDirtyFile, nil); err != nil {
		return 0, err
	}
	for _, item := range staged {
		if err := service.store.publishReplicaVersion(dir, item); err != nil {
			return 0, err
		}
	}
	for _, path := range removed {
		if err := os.Remove(path); err != nil {
			return 0, err
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return 0, err
		}
	}
	if status != delta.Status {
		if err := writeMetadataFile(dir, versionConfig, []byte(delta.Status)); err != nil {
			return 0, err
		}
	}
	if lockChanged {
		if err := writeLockConfig(dir, *delta.Lock); err != nil {
			return 0, err
		}
	}
	return count, nil
}
