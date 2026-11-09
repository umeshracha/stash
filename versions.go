package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const versionConfig = ".versioning"
const versionsPrefix = ".versions-"

func versionStatus(dir string) (string, error) {
	body, err := os.ReadFile(filepath.Join(dir, versionConfig))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	status := string(body)
	if status != "Enabled" && status != "Suspended" {
		return "", errors.New("invalid bucket versioning state")
	}
	return status, nil
}

func (s *server) bucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	if _, err := os.Stat(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	type config struct {
		XMLName   xml.Name `xml:"VersioningConfiguration"`
		XMLNS     string   `xml:"xmlns,attr,omitempty"`
		Status    string   `xml:",omitempty"`
		MfaDelete string   `xml:",omitempty"`
	}
	switch r.Method {
	case http.MethodGet:
		status, err := versionStatus(dir)
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		respond(w, 200, config{XMLNS: s3Namespace, Status: status})
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		var request config
		if err != nil || xml.Unmarshal(body, &request) != nil {
			failure(w, 400, "MalformedXML")
			return
		}
		if hash := r.Header.Get("X-Amz-Content-Sha256"); hash != "UNSIGNED-PAYLOAD" && hash != digest(string(body)) {
			failure(w, 400, "BadDigest")
			return
		}
		if request.MfaDelete != "" || request.Status != "Enabled" && request.Status != "Suspended" {
			failure(w, 400, "InvalidArgument")
			return
		}
		if request.Status == "Suspended" {
			config, err := readLockConfig(dir)
			if err != nil {
				storageError(w, err, "NoSuchBucket")
				return
			}
			if config != nil {
				failure(w, 409, "InvalidBucketState")
				return
			}
		}
		tmp, err := os.CreateTemp(dir, ".upload-")
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		defer os.Remove(tmp.Name())
		_, writeErr := tmp.WriteString(request.Status)
		err = errors.Join(writeErr, tmp.Sync(), tmp.Close())
		if err == nil {
			err = os.Rename(tmp.Name(), filepath.Join(dir, versionConfig))
		}
		if err == nil {
			err = syncDir(dir)
		}
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(200)
	default:
		failure(w, 501, "NotImplemented")
	}
}

type storedVersion struct {
	object
	path string
}

func versionsFor(dir, name string) ([]storedVersion, error) {
	var versions []storedVersion
	legacy := filepath.Join(dir, name)
	obj, err := metadataAt(legacy)
	if err == nil {
		obj.VersionID = "null"
		if err := loadProtection(dir, name, &obj); err != nil {
			return nil, err
		}
		versions = append(versions, storedVersion{obj, legacy})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	subdir := filepath.Join(dir, versionsPrefix+name)
	entries, err := os.ReadDir(subdir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, entry := range entries {
		path := filepath.Join(subdir, entry.Name())
		obj, err := metadataAt(path)
		if err != nil {
			return nil, err
		}
		if err := loadProtection(dir, name, &obj); err != nil {
			return nil, err
		}
		versions = append(versions, storedVersion{obj, path})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Sequence > versions[j].Sequence })
	return versions, nil
}

func (s *store) openVersion(dir, name, version string) (*os.File, object, error) {
	if err := checkReplicaCheckpoint(dir); err != nil {
		return nil, object{}, err
	}
	if version != "" {
		if !validVersion(version) {
			return nil, object{}, os.ErrNotExist
		}
		path := filepath.Join(dir, name)
		if version != "null" {
			path = filepath.Join(dir, versionsPrefix+name, version)
		}
		file, obj, err := openObjectFile(path)
		if err == nil {
			obj.VersionID = version
			if err := loadProtection(dir, name, &obj); err != nil {
				file.Close()
				return nil, object{}, err
			}
		}
		return file, obj, err
	}
	status, err := versionStatus(dir)
	if err != nil {
		return nil, object{}, err
	}
	if status == "" {
		return openObjectFile(filepath.Join(dir, name))
	}
	path, err := s.latestVersionPath(dir, name)
	if err != nil {
		return nil, object{}, err
	}
	file, obj, err := openObjectFile(path)
	if err != nil {
		return nil, object{}, err
	}
	if obj.VersionID == "" {
		obj.VersionID = "null"
	}
	if err := loadProtection(dir, name, &obj); err != nil {
		file.Close()
		return nil, object{}, err
	}
	return file, obj, nil
}

// Callers hold the store or version lock while looking up and opening a version.
func (s *store) latestVersionPath(dir, name string) (string, error) {
	key := filepath.Join(dir, name)
	s.versionHeadsMu.Lock()
	path := s.versionHeads[key]
	s.versionHeadsMu.Unlock()
	if path != "" {
		return path, nil
	}
	versions, err := versionsFor(dir, name)
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", os.ErrNotExist
	}
	path = versions[0].path
	s.rememberVersionHead(key, path)
	return path, nil
}

func (s *store) rememberVersionHead(key, path string) {
	s.versionHeadsMu.Lock()
	defer s.versionHeadsMu.Unlock()
	if path == "" {
		delete(s.versionHeads, key)
		return
	}
	const maxCachedHeads = 4096
	if s.versionHeads == nil {
		s.versionHeads = make(map[string]string)
	}
	if len(s.versionHeads) >= maxCachedHeads {
		for evicted := range s.versionHeads {
			delete(s.versionHeads, evicted)
			break
		}
	}
	s.versionHeads[key] = path
}

func (s *store) clearVersionHeads() {
	s.versionHeadsMu.Lock()
	clear(s.versionHeads)
	s.versionHeadsMu.Unlock()
}

func openObjectFile(path string) (*os.File, object, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, object{}, err
	}
	obj, err := readMetadata(file)
	if err != nil {
		file.Close()
		return nil, object{}, err
	}
	return file, obj, nil
}

func (s *store) publishVersion(file *os.File, dir string, obj *object) error {
	status, err := versionStatus(dir)
	if err != nil {
		return err
	}
	name := digest(obj.Key)
	if err := applyDefaultLock(dir, obj); err != nil {
		return err
	}
	if status == "" {
		err := s.commitData(file, dir, name, obj)
		if err != nil {
			s.resetReplicaFeed(dir)
		}
		return err
	}
	s.versionMu.Lock()
	defer s.versionMu.Unlock()
	head, err := s.latestVersionPath(dir, name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	obj.Sequence = time.Now().UnixNano()
	if head != "" {
		latest, err := metadataAt(head)
		if err != nil {
			return err
		}
		obj.Sequence = max(obj.Sequence, latest.Sequence+1)
	}
	cacheKey := filepath.Join(dir, name)
	publish := func(targetDir, filename string) error {
		// A failure can occur after the atomic rename, so discard the old head first.
		s.rememberVersionHead(cacheKey, "")
		if err := s.commitData(file, targetDir, filename, obj); err != nil {
			s.resetReplicaFeed(dir)
			return err
		}
		s.rememberVersionHead(cacheKey, filepath.Join(targetDir, filename))
		s.recordReplicaChange(dir, *obj, false)
		return nil
	}
	if status == "Suspended" {
		obj.VersionID = "null"
		return publish(dir, name)
	}
	var entropy [16]byte
	rand.Read(entropy[:])
	obj.VersionID = hex.EncodeToString(entropy[:])
	subdir := filepath.Join(dir, versionsPrefix+name)
	if err := os.Mkdir(subdir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return publish(subdir, obj.VersionID)
}

func (s *store) removeVersion(dir, key, version string, bypass bool) (object, error) {
	name := digest(key)
	status, err := versionStatus(dir)
	if err != nil {
		return object{}, err
	}
	if version == "" && status != "" {
		file, err := os.CreateTemp(dir, ".upload-")
		if err != nil {
			return object{}, err
		}
		defer os.Remove(file.Name())
		defer file.Close()
		marker := object{Key: key, Modified: time.Now().UTC(), DeleteMarker: true}
		err = s.publishVersion(file, dir, &marker)
		return marker, err
	}
	path := filepath.Join(dir, name)
	if version != "" && version != "null" {
		if !validVersion(version) {
			return object{VersionID: version}, nil
		}
		path = filepath.Join(dir, versionsPrefix+name, version)
	}
	obj, err := metadataAt(path)
	if errors.Is(err, os.ErrNotExist) {
		return object{VersionID: version}, nil
	}
	if err != nil {
		return object{}, err
	}
	if obj.VersionID == "" {
		obj.VersionID = "null"
	}
	if err := loadProtection(dir, name, &obj); err != nil {
		return object{}, err
	}
	if obj.Protection.blocksDelete(time.Now(), bypass) {
		return object{}, errObjectProtected
	}
	s.rememberVersionHead(filepath.Join(dir, name), "")
	if err := os.Remove(path); err != nil {
		return object{}, err
	}
	s.recordReplicaChange(dir, obj, true)
	if err := syncDir(filepath.Dir(path)); err != nil {
		return object{}, err
	}
	if err := os.Remove(protectionPath(dir, name, obj.VersionID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return object{}, err
	}

	obj.VersionID = version
	return obj, syncDir(dir)
}

func validVersion(id string) bool {
	if id == "null" {
		return true
	}
	value, err := hex.DecodeString(id)
	return err == nil && len(value) == 16 && id == strings.ToLower(id)
}

func versionNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var names []string
	for _, entry := range entries {
		name, isVersions := strings.CutPrefix(entry.Name(), versionsPrefix)
		if !isVersions && (entry.IsDir() || strings.HasPrefix(name, ".")) {
			continue
		}
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names, nil
}

type versionListEntry struct {
	XMLName      xml.Name
	Key          string
	VersionId    string
	IsLatest     bool
	LastModified string
	ETag         string `xml:",omitempty"`
	Size         *int64 `xml:",omitempty"`
	StorageClass string `xml:",omitempty"`
}

func (s *server) listVersions(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	for name, values := range q {
		switch name {
		case "versions", "prefix", "delimiter", "key-marker", "version-id-marker", "max-keys", "encoding-type", "x-id":
			if len(values) == 1 {
				continue
			}
		}
		failure(w, 400, "InvalidArgument")
		return
	}
	count := 1000
	if q.Has("max-keys") {
		n, err := strconv.Atoi(q.Get("max-keys"))
		if err != nil || n < 0 {
			failure(w, 400, "InvalidArgument")
			return
		}
		count = min(count, n)
	}
	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")
	keyMarker, versionMarker := q.Get("key-marker"), q.Get("version-id-marker")
	encoding := q.Get("encoding-type")
	if encoding != "" && encoding != "url" || versionMarker != "" && keyMarker == "" {
		failure(w, 400, "InvalidArgument")
		return
	}
	format := func(key string) string {
		if encoding == "url" {
			return encode(key, false)
		}
		return key
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	if err := checkReplicaCheckpoint(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	names, err := versionNames(dir)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	groups := make(map[string][]storedVersion)
	for _, name := range names {
		list, err := versionsFor(dir, name)
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
		}
		if len(list) == 0 {
			continue
		}
		key := list[0].Key
		suffix, ok := strings.CutPrefix(key, prefix)
		if !ok || key < keyMarker {
			continue
		}
		if index := strings.Index(suffix, delimiter); delimiter != "" && index >= 0 {
			group := prefix + suffix[:index+len(delimiter)]
			if group > keyMarker {
				groups[group] = nil
			}
			continue
		}
		groups[key] = list
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := struct {
		XMLName                                             xml.Name `xml:"ListVersionsResult"`
		XMLNS                                               string   `xml:"xmlns,attr"`
		Name, Prefix, Delimiter, KeyMarker, VersionIdMarker string
		NextKeyMarker, NextVersionIdMarker                  string `xml:",omitempty"`
		EncodingType                                        string `xml:",omitempty"`
		MaxKeys                                             int
		IsTruncated                                         bool
		Items                                               []versionResultItem `xml:",any"`
	}{XMLNS: s3Namespace, Name: bucket, Prefix: format(prefix), Delimiter: format(delimiter), KeyMarker: format(keyMarker),
		VersionIdMarker: versionMarker, EncodingType: encoding, MaxKeys: count}
	appendItem := func(item versionResultItem, key, id string) bool {
		if len(result.Items) == count {
			result.IsTruncated = count > 0
			return false
		}
		result.Items = append(result.Items, item)
		result.NextKeyMarker, result.NextVersionIdMarker = format(key), id
		return true
	}
	for _, key := range keys {
		list := groups[key]
		if list == nil {
			if !appendItem(versionResultItem{Prefix: format(key)}, key, "") {
				break
			}
			continue
		}
		start := 0
		if key == keyMarker {
			start = len(list)
			for i, item := range list {
				if item.VersionID == versionMarker {
					start = i + 1
					break
				}
			}
		}
		for i := start; i < len(list); i++ {
			obj := list[i]
			entry := versionListEntry{Key: format(key), VersionId: obj.VersionID, IsLatest: i == 0,
				LastModified: obj.Modified.Format(time.RFC3339Nano)}
			if obj.DeleteMarker {
				entry.XMLName.Local = "DeleteMarker"
			} else {
				entry.XMLName.Local = "Version"
				entry.ETag, entry.Size, entry.StorageClass = obj.ETag, &obj.Size, "STANDARD"
			}
			if !appendItem(versionResultItem{Version: &entry}, key, obj.VersionID) {
				break
			}
		}
		if result.IsTruncated {
			break
		}
	}
	if !result.IsTruncated {
		result.NextKeyMarker, result.NextVersionIdMarker = "", ""
	}
	respond(w, 200, result)
}

func setVersionHeaders(w http.ResponseWriter, obj object) {
	if obj.VersionID != "" {
		w.Header().Set("X-Amz-Version-Id", obj.VersionID)
	}
	if obj.DeleteMarker {
		w.Header().Set("X-Amz-Delete-Marker", "true")
	}
}

type versionResultItem struct {
	Version *versionListEntry
	Prefix  string
}

func (item versionResultItem) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	if item.Version != nil {
		return enc.Encode(item.Version)
	}
	return enc.EncodeElement(struct{ Prefix string }{item.Prefix}, xml.StartElement{Name: xml.Name{Local: "CommonPrefixes"}})
}
