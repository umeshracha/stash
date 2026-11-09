package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const replicationPath = "/.stash/replication/"
const replicaStateFile = ".replica"
const replicaDirtyFile = ".replica-dirty"
const maxManifest = 32 << 20

var errReplicaDirty = errors.New("replica checkpoint unavailable")

func checkReplicaCheckpoint(dir string) error {
	_, err := os.Stat(filepath.Join(dir, replicaDirtyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errReplicaDirty
}

type replicaSource struct {
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Token           string `json:"token"`
	IntervalSeconds int    `json:"interval_seconds"`
}

type replicaStatus struct {
	Source      string
	LastSuccess time.Time
	Revision    string
	Cursor      string `json:",omitempty"`
	Versions    int
	LastError   string
	Promoted    bool
}

type replication struct {
	store   *store
	exports map[string]string
	sources map[string]replicaSource
	client  *http.Client
	mu      sync.RWMutex
	status  map[string]replicaStatus
}

type replicaManifest struct {
	Lock     *lockConfiguration `json:",omitempty"`
	Status   string
	Versions []object
}

func configureReplication(cfg config, storage *store) (*replication, error) {
	service := &replication{store: storage, exports: cfg.ReplicationExports, sources: cfg.ReplicaBuckets,
		client: &http.Client{
			Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 60 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		status: map[string]replicaStatus{},
	}
	storage.replicaFeeds = make(map[string]*replicaFeed)
	for bucket, token := range service.exports {
		if !bucketName.MatchString(bucket) || len(token) < 24 {
			return nil, fmt.Errorf("invalid replication export %q", bucket)
		}
		if cfg.Cluster == nil && cfg.ReplicaBuckets[bucket].Endpoint == "" {
			storage.replicaFeeds[bucket] = newReplicaFeed()
		}
	}
	for bucket, source := range service.sources {
		u, err := url.Parse(source.Endpoint)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			u.Path != "" && u.Path != "/" || u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) ||
			!bucketName.MatchString(bucket) || !bucketName.MatchString(source.Bucket) || len(source.Token) < 24 ||
			source.IntervalSeconds < 0 || source.IntervalSeconds > 86400 {
			return nil, fmt.Errorf("invalid replica configuration for %q", bucket)
		}
		source.Endpoint = strings.TrimRight(source.Endpoint, "/")
		service.sources[bucket] = source
		dir := filepath.Join(storage.dir, bucket)
		state, err := readReplicaStatus(dir)
		expected := source.Endpoint + "/" + source.Bucket
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			if len(entries) != 0 {
				return nil, fmt.Errorf("replica bucket %q must start empty", bucket)
			}
			state = replicaStatus{Source: expected}
			if err := saveReplicaStatus(dir, state); err != nil {
				return nil, err
			}
			if err := syncDir(storage.dir); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		if state.Source != expected || state.Promoted {
			return nil, fmt.Errorf("replica bucket %q has a different source or has been promoted", bucket)
		}
		service.status[bucket] = state
	}
	for _, bucket := range cfg.PromoteBuckets {
		if !bucketName.MatchString(bucket) || service.sources[bucket].Endpoint != "" {
			return nil, fmt.Errorf("remove the replica source before promoting %q", bucket)
		}
		dir := filepath.Join(storage.dir, bucket)
		state, err := readReplicaStatus(dir)
		_, dirty := os.Stat(filepath.Join(dir, replicaDirtyFile))
		if err != nil || !errors.Is(dirty, os.ErrNotExist) || state.LastSuccess.IsZero() {
			return nil, fmt.Errorf("replica %q needs a successful checkpoint before promotion", bucket)
		}
		state.Promoted = true
		if err := saveReplicaStatus(dir, state); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readReplicaStatus(dir string) (replicaStatus, error) {
	var status replicaStatus
	data, err := os.ReadFile(filepath.Join(dir, replicaStateFile))
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(data, &status)
	return status, err
}

func saveReplicaStatus(dir string, status replicaStatus) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return writeMetadataFile(dir, replicaStateFile, data)
}

func writeMetadataFile(dir, name string, data []byte) error {
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
	return syncDir(dir)
}

func (s *server) serveReplication(w http.ResponseWriter, r *http.Request) {
	service := s.replication
	if service == nil || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	bucket, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, replicationPath), "/")
	if !bucketName.MatchString(bucket) {
		http.NotFound(w, r)
		return
	}
	if action == "status" {
		c, ok := s.authorize(r)
		if !ok || !c.allows("stash:GetReplicationStatus", bucket, "", nil) {
			http.Error(w, "access denied", 403)
			return
		}
		service.mu.RLock()
		state, ok := service.status[bucket]
		service.mu.RUnlock()
		if !ok {
			var err error
			state, err = readReplicaStatus(filepath.Join(s.store.dir, bucket))
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
		return
	}
	token, ok := service.exports[bucket]
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !ok || r.TLS == nil && !loopback(host) ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
		http.Error(w, "access denied", 403)
		return
	}
	dir := filepath.Join(s.store.dir, bucket)
	switch action {
	case "changes":
		s.serveReplicaChanges(w, r, bucket, dir)
	case "inventory":
		s.serveReplicaInventory(w, r, dir)
	case "manifest":
		s.store.mu.Lock()
		if err := checkReplicaCheckpoint(dir); err != nil {
			s.store.mu.Unlock()
			http.Error(w, "replica checkpoint unavailable", 503)
			return
		}
		manifest, err := inventory(dir)
		s.store.mu.Unlock()
		if err != nil || manifest.Status == "" {
			http.Error(w, "versioned bucket unavailable", 409)
			return
		}
		data, err := json.Marshal(manifest)
		if err != nil || len(data) > maxManifest {
			http.Error(w, "manifest too large", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case "version":
		key, version := r.URL.Query().Get("key"), r.URL.Query().Get("version")
		if !validKey(key) || !validVersion(version) {
			http.Error(w, "invalid version", 400)
			return
		}
		s.store.mu.RLock()
		s.store.versionMu.RLock()
		file, obj, err := s.store.openVersion(dir, digest(key), version)
		s.store.versionMu.RUnlock()
		s.store.mu.RUnlock()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		if obj.Key != key || obj.DeleteMarker || r.URL.Query().Get("revision") != objectRevision(obj) {
			http.Error(w, "version changed", 409)
			return
		}
		contentHash := obj.SHA256
		data, err := s.store.objectData(file, obj)
		if err != nil {
			http.Error(w, "version data unavailable", 503)
			return
		}
		defer data.Close()
		reader := io.NewSectionReader(data, 0, obj.Size)
		if contentHash == "" {
			hash := sha256.New()
			if _, err := io.Copy(hash, reader); err != nil {
				http.Error(w, "read failed", 500)
				return
			}
			contentHash = hex.EncodeToString(hash.Sum(nil))
			reader.Seek(0, io.SeekStart)
		}
		w.Header().Set("Content-Length", strconv.FormatInt(obj.Size, 10))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Stash-SHA256", contentHash)
		io.Copy(w, reader)
	default:
		http.NotFound(w, r)
	}
}

func objectRevision(obj object) string {
	// A replica may have verified and populated the digest of a legacy object.
	obj.SHA256 = ""
	obj.ErasureID = ""
	obj.Encryption = nil
	data, _ := json.Marshal(obj)
	return digest(string(data))
}

func inventory(dir string) (replicaManifest, error) {
	result, err := inventoryHeader(dir)
	if err != nil {
		return result, err
	}
	err = walkInventory(dir, func(obj object) error {
		result.Versions = append(result.Versions, obj)
		return nil
	})
	return result, err
}

func inventoryHeader(dir string) (replicaManifest, error) {
	status, err := versionStatus(dir)
	if err != nil {
		return replicaManifest{}, err
	}
	lock, err := readLockConfig(dir)
	return replicaManifest{Status: status, Lock: lock}, err
}

func walkInventory(dir string, visit func(object) error) error {
	names, err := versionNames(dir)
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		versions, err := versionsFor(dir, name)
		if err != nil {
			return err
		}
		for _, version := range versions {
			obj := version.object
			obj.ErasureID = ""
			obj.Encryption = nil
			if err := visit(obj); err != nil {
				return err
			}
		}
	}
	return nil
}

func (service *replication) start(ctx context.Context) {
	for bucket, source := range service.sources {
		go func() {
			interval := source.IntervalSeconds
			if interval == 0 {
				interval = 10
			}
			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()
			for {
				if ctx.Err() != nil {
					return
				}
				service.sync(ctx, bucket, source)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
}

func (service *replication) fetch(ctx context.Context, source replicaSource, action string, query url.Values) (*http.Response, error) {
	endpoint := source.Endpoint + replicationPath + source.Bucket + "/" + action
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+source.Token)
	result, err := service.client.Do(request)
	if err != nil {
		return nil, errors.New("replication source request failed")
	}
	if result.StatusCode != 200 {
		result.Body.Close()
		return nil, replicaHTTPError(result.StatusCode)
	}
	return result, nil
}

func (service *replication) manifest(ctx context.Context, source replicaSource, collect bool) (replicaManifest, string, error) {
	response, err := service.fetch(ctx, source, "inventory", nil)
	if err == nil {
		defer response.Body.Close()
		return readReplicaInventory(response.Body, collect)
	}
	if !errors.Is(err, replicaHTTPError(http.StatusNotFound)) {
		return replicaManifest{}, "", err
	}
	return service.legacyManifest(ctx, source)
}

func (service *replication) legacyManifest(ctx context.Context, source replicaSource) (replicaManifest, string, error) {
	var manifest replicaManifest
	response, err := service.fetch(ctx, source, "manifest", nil)
	if err != nil {
		return manifest, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifest+1))
	if err != nil || len(body) > maxManifest || json.Unmarshal(body, &manifest) != nil ||
		manifest.Status != "Enabled" && manifest.Status != "Suspended" ||
		manifest.Lock != nil && (manifest.Status != "Enabled" || !validLockConfig(*manifest.Lock)) {
		return manifest, "", errors.New("invalid replication manifest")
	}
	return manifest, digest(string(body)), nil
}

type replicaKey struct{ Key, Version string }

func (service *replication) sync(ctx context.Context, bucket string, source replicaSource) {
	service.mu.RLock()
	state := service.status[bucket]
	service.mu.RUnlock()
	revision, cursor, count, err := service.catchUp(ctx, bucket, source, state)
	if err == nil {
		state.LastError = ""
		state.LastSuccess = time.Now().UTC()
		state.Revision = revision
		state.Cursor = cursor
		state.Versions = count
		dir := filepath.Join(service.store.dir, bucket)
		err = saveReplicaStatus(dir, state)
		if err == nil {
			err = os.Remove(filepath.Join(dir, replicaDirtyFile))
			if err == nil {
				err = syncDir(dir)
			} else if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
	}
	if err != nil {
		if state.LastError != err.Error() {
			log.Printf("replication %s: %v", bucket, err)
		}
		state.LastError = err.Error()
	}
	service.mu.Lock()
	service.status[bucket] = state
	service.mu.Unlock()
}

func (service *replication) reconcile(ctx context.Context, bucket string, source replicaSource) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	manifest, revision, err := service.manifest(ctx, source, true)
	if err != nil {
		return "", 0, err
	}
	dir := filepath.Join(service.store.dir, bucket)
	type versionFingerprint struct {
		revision, checksum string
		deleteMarker       bool
	}
	existing := make(map[replicaKey]versionFingerprint)
	service.store.mu.Lock()
	local, err := inventoryHeader(dir)
	if err == nil {
		err = walkInventory(dir, func(obj object) error {
			existing[replicaKey{obj.Key, obj.VersionID}] = versionFingerprint{objectRevision(obj), obj.SHA256, obj.DeleteMarker}
			return nil
		})
	}
	service.store.mu.Unlock()
	if err != nil {
		return "", 0, err
	}
	wanted := make(map[replicaKey]bool)
	for _, obj := range manifest.Versions {
		key := replicaKey{obj.Key, obj.VersionID}
		if wanted[key] || !validKey(obj.Key) || !validVersion(obj.VersionID) || obj.Size < 0 || obj.Size > maxMultipartSize ||
			obj.DeleteMarker && obj.Size != 0 || obj.VersionID != "null" && obj.Sequence <= 0 {
			return "", 0, errors.New("invalid or duplicate replication version")
		}
		wanted[key] = true
	}
	var staged []replicaTransfer
	defer func() {
		for _, item := range staged {
			os.Remove(item.temp)
		}
	}()
	// Fetch all changed versions before publishing any of them.
	for i := len(manifest.Versions) - 1; i >= 0; i-- {
		obj := manifest.Versions[i]
		if current, ok := existing[replicaKey{obj.Key, obj.VersionID}]; ok && current.revision == objectRevision(obj) &&
			(obj.SHA256 == "" || current.checksum == obj.SHA256) && (current.checksum != "" || current.deleteMarker) {
			continue
		}
		item, err := service.transfer(ctx, source, dir, obj)
		if err != nil {
			return "", 0, err
		}
		staged = append(staged, item)
	}

	_, latest, err := service.manifest(ctx, source, false)
	if err != nil {
		return "", 0, err
	}
	if latest != revision {
		return "", 0, errors.New("source changed during replication; retrying")
	}

	service.store.mu.Lock()
	defer service.store.mu.Unlock()
	lockChanged := !reflect.DeepEqual(local.Lock, manifest.Lock)
	if local.Lock != nil && manifest.Lock == nil {
		return "", 0, errors.New("source object lock configuration disappeared")
	}
	if len(staged) != 0 || len(existing) != len(wanted) || local.Status != manifest.Status || lockChanged {
		service.store.clearVersionHeads()
		if err := writeMetadataFile(dir, replicaDirtyFile, nil); err != nil {
			return "", 0, err
		}
	}
	for _, item := range staged {
		if err := service.store.publishReplicaVersion(dir, item); err != nil {
			return "", 0, err
		}
	}
	for key := range existing {
		if wanted[key] {
			continue
		}
		path := replicaVersionPath(dir, key.Key, key.Version)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", 0, err
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return "", 0, err
		}
	}
	if local.Status != manifest.Status {
		if err := writeMetadataFile(dir, versionConfig, []byte(manifest.Status)); err != nil {
			return "", 0, err
		}
	}

	if lockChanged {
		if err := writeLockConfig(dir, *manifest.Lock); err != nil {
			return "", 0, err
		}
	}
	return revision, len(wanted), nil
}

func replicaVersionPath(dir, key, version string) string {
	name := digest(key)
	if version == "null" {
		return filepath.Join(dir, name)
	}
	return filepath.Join(dir, versionsPrefix+name, version)
}

type replicaTransfer struct {
	temp string
	obj  object
}

func (service *replication) transfer(ctx context.Context, source replicaSource, dir string, obj object) (replicaTransfer, error) {
	file, err := os.CreateTemp(dir, ".upload-")
	if err != nil {
		return replicaTransfer{}, err
	}
	keep := false
	defer func() {
		file.Close()
		if !keep {
			os.Remove(file.Name())
		}
	}()
	if !obj.DeleteMarker {
		q := url.Values{"key": {obj.Key}, "version": {obj.VersionID}, "revision": {objectRevision(obj)}}
		response, err := service.fetch(ctx, source, "version", q)
		if err != nil {
			return replicaTransfer{}, err
		}
		defer response.Body.Close()
		out, finish, err := service.store.stagingWriter(file, obj.Key)
		if err != nil {
			return replicaTransfer{}, err
		}
		hash := sha256.New()
		count, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(response.Body, obj.Size+1))
		actual := hex.EncodeToString(hash.Sum(nil))
		if err != nil || count != obj.Size || actual != response.Header.Get("X-Stash-SHA256") ||
			obj.SHA256 != "" && obj.SHA256 != actual {
			return replicaTransfer{}, errors.New("replica transfer size or checksum mismatch")
		}
		obj.SHA256 = actual
		obj.Encryption, err = finish()
		if err != nil {
			return replicaTransfer{}, err
		}
	}
	if err := file.Close(); err != nil {
		return replicaTransfer{}, err
	}
	keep = true
	return replicaTransfer{file.Name(), obj}, nil
}

func (s *store) publishReplicaVersion(dir string, item replicaTransfer) error {
	obj := item.obj
	path := replicaVersionPath(dir, obj.Key, obj.VersionID)
	subdir := filepath.Dir(path)
	if subdir != dir {
		if err := os.Mkdir(subdir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(item.temp, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return s.commitData(file, subdir, filepath.Base(path), &obj)
}
