package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"stash/internal/encryption"
	"stash/internal/erasure"
	"stash/internal/etcd"
	"stash/internal/fsutil"
)

const clusterBinding = ".cluster-bound"
const clusterInitialized = ".cluster-initialized"
const maxClusterSnapshot = 768 << 10
const maxClusterDecoded = 16 << 20

type clusterConfig struct {
	CAFile     string   `json:"ca_file"`
	ClientCert string   `json:"client_cert"`
	ClientKey  string   `json:"client_key"`
	Endpoints  []string `json:"endpoints"`
	Name       string   `json:"name"`
	Token      string   `json:"token"`
}

type metadataCluster struct {
	config       clusterConfig
	key          string
	etcd         *etcd.Client
	mu           sync.Mutex
	revision     string
	partitions   map[string]metadataPartition
	partitioned  bool
	generation   string
	readRevision string
	store        *store
}

type metadataSnapshot struct {
	Encryption []byte `json:",omitempty"`
	Layout     []byte
	Entries    map[string][]byte
}

func configureCluster(storage *store, cfg config, allowBootstrap bool) (*metadataCluster, error) {
	dir := storage.dir
	binding, err := os.ReadFile(filepath.Join(dir, clusterBinding))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if cfg.Cluster == nil {
		if len(binding) != 0 {
			return nil, errors.New("this data directory requires its cluster configuration")
		}
		return nil, nil
	}
	if cfg.Erasure == nil || len(cfg.Erasure.Nodes) == 0 || cfg.ShardNodeToken != "" ||
		len(cfg.ReplicaBuckets) != 0 || len(cfg.PromoteBuckets) != 0 {
		return nil, errors.New("cluster metadata requires network shard nodes and dedicated coordinator data directories")
	}
	config := *cfg.Cluster
	if !bucketName.MatchString(config.Name) || len(config.Endpoints) == 0 ||
		len(binding) != 0 && string(binding) != config.Name {
		return nil, errors.New("invalid cluster name, endpoints, or local cluster binding")
	}
	config.Endpoints = append([]string(nil), config.Endpoints...)
	for i, endpoint := range config.Endpoints {
		parsed, err := erasure.ValidateNode(erasure.Node{Endpoint: endpoint, Token: strings.Repeat("x", 24)})
		if err != nil {
			return nil, fmt.Errorf("invalid etcd endpoint %d", i+1)
		}
		config.Endpoints[i] = parsed.Endpoint
	}
	if len(binding) == 0 {
		names, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if name.Name() != ".lock" && name.Name() != encryption.BindingFile {
				return nil, errors.New("start a cluster coordinator with an empty local data directory")
			}
		}
		if err := fsutil.WriteFileAtomic(dir, clusterBinding, []byte(config.Name)); err != nil {
			return nil, err
		}
	}
	identity, err := os.ReadFile(filepath.Join(dir, clusterInitialized))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	client, err := etcd.New(config.Endpoints, config.Token, config.CAFile, config.ClientCert, config.ClientKey, string(identity))
	if err != nil {
		return nil, err
	}
	cluster := &metadataCluster{
		config: config, key: base64.StdEncoding.EncodeToString([]byte("/stash/metadata/" + config.Name + "/v1")),
		store: storage, etcd: client,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	snapshot, revision, err := cluster.read(ctx)
	if err != nil {
		return nil, err
	}
	if revision == "0" {
		if !allowBootstrap {
			return nil, errors.New("cluster metadata is missing")
		}
		if len(identity) != 0 {
			return nil, errors.New("initialized cluster metadata is missing")
		}
		// Bind the local layout before offering it as the cluster's first revision.
		// On a concurrent bootstrap, discard this candidate and use the winner.
		if _, err := erasure.Open(dir, cfg.Erasure); err != nil {
			return nil, err
		}
		candidate, err := newClusterRoot(dir)
		if err != nil {
			return nil, err
		}
		_, err = cluster.commit(ctx, revision, candidate)
		if err != nil {
			return nil, err
		}
		snapshot, revision, err = cluster.read(ctx)
		if err != nil {
			return nil, err
		}
	}
	if revision == "0" {
		return nil, etcd.ErrQuorum
	}
	var expectedLayout []byte
	if len(identity) != 0 {
		expectedLayout, err = os.ReadFile(filepath.Join(dir, erasure.LayoutFile))
		if err != nil {
			return nil, err
		}
	}
	if !isPartitionedRoot(snapshot) {
		if err := cluster.migrateMetadata(ctx, revision, snapshot, expectedLayout); err != nil {
			return nil, err
		}
		snapshot, revision, err = cluster.read(ctx)
		if err != nil {
			return nil, err
		}
	}
	if isPartitionedRoot(snapshot) {
		if err := cluster.refreshPartitions(ctx, snapshot, expectedLayout); err != nil {
			return nil, err
		}
		cluster.partitioned = true
	} else {
		return nil, etcd.ErrQuorum
	}
	if err := fsutil.WriteFileAtomic(dir, clusterInitialized, []byte(cluster.etcd.Identity())); err != nil {
		return nil, err
	}
	cluster.revision = revision
	return cluster, nil
}

func (cluster *metadataCluster) read(ctx context.Context) ([]byte, string, error) {
	result, err := cluster.etcd.Range(ctx, map[string]string{"key": cluster.key})
	if err != nil {
		return nil, "", err
	}
	cluster.readRevision = result.Header.Revision
	if len(result.KVs) == 0 {
		return nil, "0", nil
	}
	if len(result.KVs) != 1 || len(result.KVs[0].Value) == 0 {
		return nil, "", etcd.ErrQuorum
	}
	version := result.KVs[0]
	if n, err := strconv.ParseInt(version.Revision, 10, 64); err != nil || n <= 0 {
		return nil, "", etcd.ErrQuorum
	}
	return version.Value, version.Revision, nil
}

func (cluster *metadataCluster) commit(ctx context.Context, revision string, data []byte) (string, error) {
	transaction := map[string]any{
		"compare": []any{map[string]string{"target": "MOD", "result": "EQUAL", "key": cluster.key, "mod_revision": revision}},
		"success": []any{map[string]any{"request_put": map[string]any{"key": cluster.key, "value": data}}},
	}
	return cluster.etcd.Transaction(ctx, transaction)
}

func snapshotMetadata(dir string) ([]byte, error) {
	return snapshotBucketMetadata(dir, "")
}

func snapshotBucketMetadata(dir, bucket string) ([]byte, error) {
	layout, err := os.ReadFile(filepath.Join(dir, erasure.LayoutFile))
	if err != nil {
		return nil, err
	}
	snapshot := metadataSnapshot{Layout: layout, Entries: map[string][]byte{}}
	if bucket == "" {
		snapshot.Encryption, err = clusterEncryptionBinding(dir)
		if err != nil {
			return nil, err
		}
	}
	total := len(layout)
	rootPath := dir
	if bucket != "" {
		rootPath = filepath.Join(dir, bucket)
		if _, err := os.Stat(rootPath); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
	}
	err = filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		name, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		root, _, _ := strings.Cut(name, string(filepath.Separator))
		if !bucketName.MatchString(root) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".upload-") || strings.HasPrefix(entry.Name(), ".start-mp-") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			snapshot.Entries[name] = nil
		} else {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !entry.Type().IsRegular() || info.Size() > maxMetadata+4 {
				return errors.New("cluster snapshot contains an unexpected or oversized metadata file")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Preserve an empty file as a file rather than a directory.
			if body == nil {
				body = []byte{}
			}
			snapshot.Entries[name] = body
			total += len(body)
		}
		total += len(name) + 8
		if total > maxClusterDecoded/2 {
			return errors.New("cluster metadata snapshot is too large")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return encodeClusterSnapshot(snapshot)
}

func encodeClusterSnapshot(snapshot metadataSnapshot) ([]byte, error) {
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	if err := errors.Join(json.NewEncoder(compressed).Encode(snapshot), compressed.Close()); err != nil {
		return nil, err
	}
	if buffer.Len() > maxClusterSnapshot {
		return nil, errors.New("cluster metadata snapshot exceeds its 768 KiB compressed limit")
	}
	return buffer.Bytes(), nil
}

func decodeClusterSnapshot(encoded []byte) (metadataSnapshot, error) {
	var snapshot metadataSnapshot
	if len(encoded) > maxClusterSnapshot {
		return snapshot, errors.New("cluster snapshot is too large")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		return snapshot, err
	}
	defer compressed.Close()
	body, err := io.ReadAll(io.LimitReader(compressed, maxClusterDecoded+1))
	if err != nil || len(body) > maxClusterDecoded || json.Unmarshal(body, &snapshot) != nil || len(snapshot.Layout) == 0 {
		return snapshot, errors.New("invalid cluster snapshot")
	}
	return snapshot, nil
}

func restoreMetadata(dir string, encoded, expectedLayout []byte) error {
	snapshot, err := decodeClusterSnapshot(encoded)
	if err != nil {
		return err
	}
	localEncryption, err := clusterEncryptionBinding(dir)
	if err != nil {
		return err
	}
	if !bytes.Equal(localEncryption, snapshot.Encryption) {
		return errors.New("cluster coordinators must use the cluster encryption configuration")
	}
	if len(expectedLayout) != 0 && !bytes.Equal(expectedLayout, snapshot.Layout) {
		return errors.New("cluster shard layout changed")
	}
	tmp, err := os.MkdirTemp(dir, ".cluster-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := materializeMetadata(tmp, "", snapshot.Entries); err != nil {
		return err
	}
	current, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range current {
		if entry.IsDir() && (bucketName.MatchString(entry.Name()) || strings.HasPrefix(entry.Name(), ".cluster-restore-")) &&
			filepath.Join(dir, entry.Name()) != tmp {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	buckets, err := os.ReadDir(tmp)
	if err != nil {
		return err
	}
	for _, bucket := range buckets {
		if !bucket.IsDir() {
			return errors.New("invalid bucket in cluster snapshot")
		}
		if err := os.Rename(filepath.Join(tmp, bucket.Name()), filepath.Join(dir, bucket.Name())); err != nil {
			return err
		}
	}
	return fsutil.WriteFileAtomic(dir, erasure.LayoutFile, snapshot.Layout)
}

func materializeMetadata(tmp, bucket string, entries map[string][]byte) error {
	for name, contents := range entries {
		root, _, _ := strings.Cut(name, string(filepath.Separator))
		if !filepath.IsLocal(name) || filepath.Clean(name) != name || !bucketName.MatchString(root) || bucket != "" && root != bucket {
			return errors.New("invalid path in cluster snapshot")
		}
		path := filepath.Join(tmp, name)
		if contents == nil {
			if err := os.MkdirAll(path, 0700); err != nil {
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(path, contents, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (cluster *metadataCluster) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		cluster.mu.Lock()
		defer cluster.mu.Unlock()
		snapshot, revision, err := cluster.refresh(r.Context())
		if err != nil {
			failure(w, 503, "ServiceUnavailable")
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		result := httptest.NewRecorder()
		next.ServeHTTP(result, r)
		if result.Code < 200 || result.Code >= 300 {
			// Some filesystem operations may fail after modifying the local cache.
			cluster.revision = ""
		} else if cluster.partitioned {
			bucket, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
			if err := cluster.commitPartition(r.Context(), bucket, revision); err != nil {
				cluster.revision = ""
				failure(w, 503, "ServiceUnavailable")
				return
			}
		} else {
			updated, err := snapshotMetadata(cluster.store.dir)
			if err == nil && !bytes.Equal(updated, snapshot) {
				cluster.revision, err = cluster.commit(r.Context(), revision, updated)
			}
			if err != nil || cluster.revision == "" {
				cluster.revision = ""
				failure(w, 503, "ServiceUnavailable")
				return
			}
		}
		for name, values := range result.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(result.Code)
		w.Write(result.Body.Bytes())
	})
}

// refresh runs with the coordinator lock held.
func (cluster *metadataCluster) refresh(ctx context.Context) ([]byte, string, error) {
	snapshot, revision, err := cluster.read(ctx)
	if err != nil {
		return nil, "", err
	}
	if revision == "0" {
		return nil, "", etcd.ErrQuorum
	}
	if isPartitionedRoot(snapshot) {
		layout, err := os.ReadFile(filepath.Join(cluster.store.dir, erasure.LayoutFile))
		if err != nil {
			return nil, "", err
		}
		if err := cluster.refreshPartitions(ctx, snapshot, layout); err != nil {
			cluster.revision = ""
			return nil, "", err
		}
		cluster.partitioned = true
		cluster.revision = revision
		return snapshot, revision, nil
	}
	if cluster.partitioned {
		return nil, "", etcd.ErrQuorum
	}
	if revision != cluster.revision {
		layout, err := os.ReadFile(filepath.Join(cluster.store.dir, erasure.LayoutFile))
		if err != nil {
			cluster.revision = ""
			return nil, "", err
		}
		cluster.store.clearVersionHeads()
		if err := restoreMetadata(cluster.store.dir, snapshot, layout); err != nil {
			cluster.revision = ""
			return nil, "", err
		}
		cluster.revision = revision
	}
	return snapshot, revision, nil
}

func clusterEncryptionBinding(dir string) ([]byte, error) {
	value, err := os.ReadFile(filepath.Join(dir, encryption.BindingFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return value, err
}
