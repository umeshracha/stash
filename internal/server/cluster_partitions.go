package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type clusterRoot struct {
	Format     string
	Generation string
	Layout     []byte
	Encryption []byte
}

type metadataPartition struct {
	revision string
	digest   string
}

func newClusterRoot(dir string) ([]byte, error) {
	layout, err := os.ReadFile(filepath.Join(dir, erasureLayout))
	if err != nil {
		return nil, err
	}
	encryption, err := clusterEncryptionBinding(dir)
	if err != nil {
		return nil, err
	}
	return json.Marshal(partitionRoot(layout, encryption))
}

func partitionRoot(layout, encryption []byte) clusterRoot {
	var generation [16]byte
	rand.Read(generation[:])
	return clusterRoot{Format: "bucket-partitions-v1", Generation: hex.EncodeToString(generation[:]), Layout: layout, Encryption: encryption}
}

func isPartitionedRoot(data []byte) bool { return len(data) != 0 && data[0] == '{' }

func (cluster *metadataCluster) bucketPrefix(generation string) string {
	return "/stash/metadata/" + cluster.config.Name + "/buckets/" + generation + "/"
}

func (cluster *metadataCluster) refreshPartitions(ctx context.Context, encoded, expectedLayout []byte) error {
	var root clusterRoot
	if json.Unmarshal(encoded, &root) != nil || root.Format != "bucket-partitions-v1" || len(root.Layout) == 0 {
		return errors.New("invalid cluster metadata root")
	}
	dir := cluster.store.dir
	encryption, err := clusterEncryptionBinding(dir)
	if err != nil {
		return err
	}
	active, err := clusterActiveKey(encryption, root.Encryption)
	if err != nil {
		return err
	}
	if active != "" && cluster.store.encryption == nil {
		return errEncryptionUnavailable
	}
	if len(expectedLayout) != 0 && !bytes.Equal(expectedLayout, root.Layout) {
		return errors.New("cluster shard layout changed")
	}
	generation, err := hex.DecodeString(root.Generation)
	if err != nil || len(generation) != 16 {
		return errors.New("invalid cluster metadata generation")
	}
	prefix := cluster.bucketPrefix(root.Generation)
	end := prefix[:len(prefix)-1] + "0"
	updated := make(map[string]metadataPartition)
	readRevision := cluster.readRevision
	if revision, err := strconv.ParseInt(readRevision, 10, 64); err != nil || revision <= 0 {
		return errMetadataQuorum
	}
	for start := prefix; ; {
		query := map[string]any{
			"key": []byte(start), "range_end": []byte(end), "keys_only": true,
			"limit": "1000", "sort_order": "ASCEND", "sort_target": "KEY",
		}
		query["revision"] = readRevision
		var page etcdRange
		if err := cluster.call(ctx, "/v3/kv/range", query, &page); err != nil {
			return err
		}
		for _, item := range page.KVs {
			key, err := base64.StdEncoding.DecodeString(item.Key)
			bucket, valid := strings.CutPrefix(string(key), prefix)
			revision, revErr := strconv.ParseInt(item.Revision, 10, 64)
			if err != nil || !valid || !bucketName.MatchString(bucket) || revErr != nil || revision <= 0 {
				return errMetadataQuorum
			}
			previous := cluster.partitions[bucket]
			if cluster.revision != "" && cluster.generation == root.Generation && previous.revision == item.Revision {
				updated[bucket] = previous
			} else {
				var value etcdRange
				err := cluster.call(ctx, "/v3/kv/range", map[string]string{"key": item.Key, "revision": readRevision}, &value)
				if err != nil {
					return err
				}
				if len(value.KVs) != 1 || value.KVs[0].Revision != item.Revision {
					return errMetadataQuorum
				}
				data := value.KVs[0].Value
				cluster.store.clearVersionHeads()
				if err := restoreBucketPartition(dir, bucket, data, root); err != nil {
					return err
				}
				updated[bucket] = metadataPartition{item.Revision, digest(string(data))}
			}
			start = string(key) + "\x00"
		}
		if !page.More {
			break
		}
		if len(page.KVs) == 0 {
			return errMetadataQuorum
		}
	}

	local, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range local {
		name := entry.Name()
		if entry.IsDir() && (bucketName.MatchString(name) && updated[name].revision == "" ||
			strings.HasPrefix(name, ".cluster-restore-")) {
			cluster.store.clearVersionHeads()
			if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	if len(expectedLayout) == 0 {
		if err := writeMetadataFile(dir, erasureLayout, root.Layout); err != nil {
			return err
		}
	}
	if active != "" {
		cluster.store.encryption.active = active
	}
	cluster.partitions = updated
	cluster.generation = root.Generation
	return nil
}

func restoreBucketPartition(dir, bucket string, data []byte, root clusterRoot) error {
	snapshot, err := decodeClusterSnapshot(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(snapshot.Layout, root.Layout) {
		return errors.New("partition metadata does not match cluster layout")
	}
	if len(snapshot.Encryption) != 0 {
		// Older partitions embed the binding that was active when they were written.
		if _, err := clusterActiveKey(root.Encryption, snapshot.Encryption); err != nil {
			return err
		}
	}
	if value, exists := snapshot.Entries[bucket]; !exists || value != nil {
		return errors.New("partition is missing its bucket directory")
	}
	tmp, err := os.MkdirTemp(dir, ".cluster-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := materializeMetadata(tmp, bucket, snapshot.Entries); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(dir, bucket)); err != nil {
		return err
	}
	return os.Rename(filepath.Join(tmp, bucket), filepath.Join(dir, bucket))
}

func (cluster *metadataCluster) commitPartition(ctx context.Context, bucket, rootRevision string) error {
	if !bucketName.MatchString(bucket) {
		return nil
	}
	data, err := snapshotBucketMetadata(cluster.store.dir, bucket)
	if err != nil {
		return err
	}
	previous := cluster.partitions[bucket]
	checksum := digest(string(data))
	if data == nil && previous.revision == "" || data != nil && previous.digest == checksum {
		return nil
	}
	key := base64.StdEncoding.EncodeToString([]byte(cluster.bucketPrefix(cluster.generation) + bucket))
	revision := previous.revision
	if revision == "" {
		revision = "0"
	}
	operation := map[string]any{"request_put": map[string]any{"key": key, "value": data}}
	if data == nil {
		operation = map[string]any{"request_delete_range": map[string]string{"key": key}}
	}
	transaction := map[string]any{
		"compare": []any{
			map[string]string{"target": "MOD", "result": "EQUAL", "key": cluster.key, "mod_revision": rootRevision},
			map[string]string{"target": "MOD", "result": "EQUAL", "key": key, "mod_revision": revision},
		},
		"success": []any{operation},
	}
	committed, err := cluster.runTransaction(ctx, transaction)
	if err != nil {
		return err
	}
	if committed == "" {
		return errMetadataQuorum
	}
	if data == nil {
		delete(cluster.partitions, bucket)
	} else {
		cluster.partitions[bucket] = metadataPartition{committed, checksum}
	}
	return nil
}

// Stage a legacy snapshot under an isolated generation, then publish the root
// with the legacy revision as a fence. Legacy coordinators cannot parse the new root.
func (cluster *metadataCluster) migrateMetadata(ctx context.Context, revision string, data, expectedLayout []byte) error {
	snapshot, err := decodeClusterSnapshot(data)
	if err != nil {
		return err
	}
	localEncryption, err := clusterEncryptionBinding(cluster.store.dir)
	if err != nil {
		return err
	}
	if _, err := clusterActiveKey(localEncryption, snapshot.Encryption); err != nil {
		return err
	}
	if len(expectedLayout) != 0 && !bytes.Equal(expectedLayout, snapshot.Layout) {
		return errors.New("legacy metadata does not match cluster layout")
	}
	root := partitionRoot(snapshot.Layout, snapshot.Encryption)
	prefix := cluster.bucketPrefix(root.Generation)
	partitions := make(map[string]map[string][]byte)
	for name, value := range snapshot.Entries {
		bucket, _, _ := strings.Cut(name, string(filepath.Separator))
		if !bucketName.MatchString(bucket) || !filepath.IsLocal(name) || filepath.Clean(name) != name {
			return errors.New("invalid path in legacy cluster snapshot")
		}
		if partitions[bucket] == nil {
			partitions[bucket] = make(map[string][]byte)
		}
		partitions[bucket][name] = value
	}
	for bucket, entries := range partitions {
		if value, exists := entries[bucket]; !exists || value != nil {
			return errors.New("legacy snapshot is missing its bucket directory")
		}
		partition, err := encodeClusterSnapshot(metadataSnapshot{Layout: root.Layout, Entries: entries})
		if err != nil {
			return err
		}
		key := base64.StdEncoding.EncodeToString([]byte(prefix + bucket))
		transaction := map[string]any{
			"compare": []any{map[string]string{"target": "MOD", "result": "EQUAL", "key": cluster.key, "mod_revision": revision}},
			"success": []any{map[string]any{"request_put": map[string]any{"key": key, "value": partition}}},
		}
		committed, err := cluster.runTransaction(ctx, transaction)
		if err != nil {
			return err
		}
		if committed == "" {
			return errMetadataQuorum
		}
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return err
	}
	_, err = cluster.commit(ctx, revision, encoded)
	// On a competing activation, the caller reloads the authoritative root.
	return err
}
