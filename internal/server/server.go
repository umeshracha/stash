package server

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stash/internal/encryption"
	"stash/internal/erasure"
	"stash/internal/fsutil"
	"stash/internal/sigv4"
	"stash/internal/upload"
)

type server struct {
	store       *store
	credentials map[string]credential
	region      string
	replication *replication
	admin       *adminConsole
}

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	xml.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, code string) {
	failureMessage(w, status, code, code)
}

func failureMessage(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, struct {
		XMLName xml.Name `xml:"Error"`
		Code    string
		Message string
	}{Code: code, Message: message})
}

func (c credential) permission(bucket string) string {
	if permission, exists := c.Buckets[bucket]; exists {
		return permission
	}
	return c.Buckets["*"]
}

type bucketEntry struct {
	Name         string
	CreationDate string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, adminPath) {
		if s.admin == nil {
			http.NotFound(w, r)
			return
		}
		s.admin.serve(w, r, s)
		return
	}
	if strings.HasPrefix(r.URL.Path, replicationPath) {
		s.serveReplication(w, r)
		return
	}
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
		if s.store.erasure != nil && !s.store.erasure.Ready() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
		return
	}
	c, err := s.authorize(r)
	if err != nil {
		s.denyAuth(w, err)
		return
	}
	if traffic, ok := r.Context().Value(analyticsRequestContext{}).(*requestTraffic); ok {
		traffic.app = c.Label
		traffic.credential = c.id
		if traffic.app == "" {
			traffic.app = "authenticated"
		}
		bucket, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if bucketName.MatchString(bucket) {
			traffic.bucket = bucket
		}
	}
	w.Header().Set("X-Amz-Bucket-Region", s.region)
	query := r.URL.Query()
	// Some SDKs include a signed operation hint in otherwise identical requests.
	query.Del("x-id")
	presigned := query.Has("X-Amz-Algorithm")
	if presigned {
		sigv4.RemovePresignParams(query)
		if len(query) != 0 || r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPut ||
			r.Header.Get("X-Amz-Copy-Source") != "" || r.Header.Get("X-Amz-Content-Sha256") != "" {
			failure(w, 501, "NotImplemented")
			return
		}
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	}
	if !presigned && r.URL.Path == "/" && r.Method == http.MethodGet && len(query) == 0 {
		_, denied := c.policyDecision("s3:ListAllMyBuckets", "*", nil)
		if denied {
			failure(w, 403, "AccessDenied")
			return
		}
		s.listBuckets(w, c)
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !bucketName.MatchString(bucket) || key != "" && !validKey(key) {
		failure(w, 400, "InvalidArgument")
		return
	}
	action := requestAction(r)
	batch := key == "" && r.Method == http.MethodPost && len(query) == 1 && query.Has("delete")
	var prefix *string
	if key == "" && r.Method == http.MethodGet && (query.Has("list-type") || query.Has("versions")) {
		if len(query["prefix"]) > 1 {
			failure(w, 400, "InvalidArgument")
			return
		}
		value := query.Get("prefix")
		prefix = &value
	}
	if !batch && action == "" {
		failure(w, 501, "NotImplemented")
		return
	}
	if !batch && !s.allows(c, action, bucket, key, prefix) {
		failure(w, 403, "AccessDenied")
		return
	}

	bucketDir := filepath.Join(s.store.dir, bucket)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		state, err := readReplicaStatus(bucketDir)
		if err == nil && !state.Promoted || err != nil && !errors.Is(err, os.ErrNotExist) {
			failure(w, 403, "AccessDenied")
			return
		}
	}

	if query.Has("object-lock") && (key != "" || len(query) != 1 || len(query["object-lock"]) != 1 ||
		r.Method != http.MethodGet && r.Method != http.MethodPut) {
		failure(w, 400, "InvalidArgument")
		return
	}
	if key == "" {
		if presigned {
			failure(w, 501, "NotImplemented")
			return
		}
		switch {
		case len(query) == 0:
			s.bucket(w, r, bucket, c)
		case r.Method == http.MethodGet && len(query) == 1 && query.Has("location"):
			region := s.region
			if region == "us-east-1" {
				region = ""
			}
			if _, err := os.Stat(filepath.Join(s.store.dir, bucket)); err != nil {
				storageError(w, err, "NoSuchBucket")
				return
			}
			respond(w, 200, struct {
				XMLName xml.Name `xml:"LocationConstraint"`
				XMLNS   string   `xml:"xmlns,attr"`
				Region  string   `xml:",chardata"`
			}{XMLNS: s3Namespace, Region: region})
		case len(query) == 1 && query.Has("object-lock") && (r.Method == http.MethodGet || r.Method == http.MethodPut):
			s.bucketLock(w, r, bucket)
		case len(query) == 1 && query.Has("lifecycle"):
			s.bucketLifecycle(w, r, bucket)
		case len(query) == 1 && query.Has("policy"):
			s.bucketPolicy(w, r, bucket)
		case len(query) == 1 && query.Has("versioning"):
			s.bucketVersioning(w, r, bucket)
		case r.Method == http.MethodGet && query.Has("versions"):
			s.listVersions(w, r, bucket)
		case r.Method == http.MethodPost && len(query) == 1 && query.Has("delete"):
			s.deleteObjects(w, r, bucket, c)
		case r.Method == http.MethodGet && query.Get("list-type") == "2":
			s.listObjects(w, r, bucket)
		default:
			failure(w, 501, "NotImplemented")
		}
		return
	}
	if query.Has("retention") || query.Has("legal-hold") {
		if (len(query) == 1 || len(query) == 2 && len(query["versionId"]) == 1 && query.Get("versionId") != "") &&
			query.Has("retention") != query.Has("legal-hold") && len(query["retention"]) <= 1 && len(query["legal-hold"]) <= 1 && (r.Method == http.MethodGet || r.Method == http.MethodPut) {
			s.versionProtection(w, r, c, bucket, key, query.Get("versionId"), query.Has("legal-hold"))
		} else {
			failure(w, 400, "InvalidArgument")
		}
		return
	}
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		var allowed bool
		r, allowed = s.protectUpload(w, r, c, bucket, key)
		if !allowed {
			return
		}
	}
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-server-side-encryption-") {
			failure(w, 501, "NotImplemented")
			return
		}
	}
	if mode := r.Header.Get("X-Amz-Server-Side-Encryption"); mode != "" {
		if mode != "AES256" || s.store.encryption == nil ||
			r.Method != http.MethodPut && !(r.Method == http.MethodPost && query.Has("uploads")) || query.Has("uploadId") {
			failure(w, 400, "InvalidRequest")
			return
		}
	}
	if r.Header.Get("X-Amz-Tagging") != "" ||
		r.Method == http.MethodPut && (r.Header.Get("If-Match") != "" || r.Header.Get("If-None-Match") != "") {
		failure(w, 501, "NotImplemented")
		return
	}
	if r.Header.Get("X-Amz-Copy-Source") != "" && !query.Has("uploadId") {
		if r.Method != http.MethodPut || len(query) != 0 {
			failure(w, 501, "NotImplemented")
			return
		}
		s.copyObject(w, r, c, bucket, key)
		return
	}
	mode := r.Header.Get("X-Amz-Content-Sha256")
	if r.Method == http.MethodPut && upload.IsStreaming(mode) {
		if err := upload.Unwrap(r, c.Secret, s.region, mode, maxObject); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
	}
	if query.Has("uploads") || query.Has("uploadId") {
		s.multipart(w, r, bucket, key, query, c)
		return
	}
	version := ""
	if len(query) != 0 {
		if len(query) != 1 || len(query["versionId"]) != 1 || r.Method == http.MethodPut {
			failure(w, 501, "NotImplemented")
			return
		}
		version = query.Get("versionId")
		if version == "" {
			failure(w, 400, "InvalidArgument")
			return
		}
	}
	s.object(w, r, bucket, key, version, c)
}

func storageError(w http.ResponseWriter, err error, missing string) {
	switch {
	case errors.Is(err, errObjectProtected):
		failure(w, 403, "AccessDenied")
	case errors.Is(err, errObjectLockDisabled):
		failure(w, 400, "InvalidRequest")
	case errors.Is(err, errReplicaDirty), errors.Is(err, erasure.ErrQuorum), errors.Is(err, encryption.ErrUnavailable):
		failure(w, 503, "ServiceUnavailable")
	case errors.Is(err, os.ErrNotExist):
		failure(w, 404, missing)
	case errors.Is(err, upload.ErrChecksum):
		failure(w, 400, "BadDigest")
	case errors.Is(err, upload.ErrTooLarge):
		failure(w, 413, "EntityTooLarge")
	default:
		failure(w, 500, "InternalError")
	}
}

func (s *server) listBuckets(w http.ResponseWriter, c credential) {
	entries, err := os.ReadDir(s.store.dir)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	result := struct {
		XMLName xml.Name      `xml:"ListAllMyBucketsResult"`
		XMLNS   string        `xml:"xmlns,attr"`
		Buckets []bucketEntry `xml:"Buckets>Bucket"`
	}{XMLNS: s3Namespace}
	for _, entry := range entries {
		if !entry.IsDir() || !bucketName.MatchString(entry.Name()) ||
			!s.allows(c, "s3:ListBucket", entry.Name(), "", nil) && !c.allows("s3:ListAllMyBuckets", "", "", nil) {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		result.Buckets = append(result.Buckets, bucketEntry{entry.Name(), info.ModTime().UTC().Format(time.RFC3339)})
	}
	respond(w, 200, result)
}

func (s *server) bucket(w http.ResponseWriter, r *http.Request, bucket string, c credential) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	path := filepath.Join(s.store.dir, bucket)
	switch r.Method {
	case http.MethodPut:
		lock := r.Header.Get("X-Amz-Bucket-Object-Lock-Enabled") == "true"
		if lock && (!s.allows(c, "s3:PutBucketObjectLockConfiguration", bucket, "", nil) ||
			!s.allows(c, "s3:PutBucketVersioning", bucket, "", nil)) {
			failure(w, 403, "AccessDenied")
			return
		}
		if r.ContentLength != 0 {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
			var request struct{ LocationConstraint string }
			if err != nil || digest(string(body)) != r.Header.Get("X-Amz-Content-Sha256") ||
				xml.Unmarshal(body, &request) != nil || request.LocationConstraint != s.region {
				failure(w, 400, "InvalidLocationConstraint")
				return
			}
		}
		var err error
		if lock {
			err = createLockedBucket(s.store.dir, path)
		} else {
			err = os.Mkdir(path, 0700)
		}
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				failure(w, 409, "BucketAlreadyOwnedByYou")
			} else {
				storageError(w, err, "NoSuchBucket")
			}
			return
		}

		if err := fsutil.SyncDir(s.store.dir); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.Header().Set("Location", "/"+bucket)
		w.WriteHeader(200)
	case http.MethodHead:
		if _, err := os.Stat(path); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(200)
	case http.MethodDelete:
		entries, err := os.ReadDir(path)
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		for _, entry := range entries {
			name := entry.Name()
			if name == versionConfig || name == lifecycleFile || name == objectLockFile || strings.HasPrefix(name, objectLockPrefix) || name == bucketPolicyFile || name == replicaStateFile || strings.HasPrefix(name, ".upload-") {
				continue
			}
			if strings.HasPrefix(name, versionsPrefix) {
				files, err := os.ReadDir(filepath.Join(path, name))
				if err != nil {
					storageError(w, err, "NoSuchBucket")
					return
				}
				if len(files) == 0 {
					continue
				}
			}
			failure(w, 409, "BucketNotEmpty")
			return
		}
		for _, entry := range entries {
			if err := os.RemoveAll(filepath.Join(path, entry.Name())); err != nil {
				storageError(w, err, "NoSuchBucket")
				return
			}
		}
		s.store.resetReplicaFeed(path)
		if err := os.Remove(path); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		if err := fsutil.SyncDir(s.store.dir); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(204)
	default:
		failure(w, 501, "NotImplemented")
	}
}

func (s *server) object(w http.ResponseWriter, r *http.Request, bucket, key, version string, c credential) {
	dir := filepath.Join(s.store.dir, bucket)
	switch r.Method {
	case http.MethodPut:
		payload := r.Header.Get("X-Amz-Content-Sha256")
		if strings.HasPrefix(payload, "STREAMING-") {
			failure(w, 501, "NotImplemented")
			return
		}
		obj, err := s.store.put(bucket, key, r)
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		setVersionHeaders(w, obj)
		setEncryptionHeader(w, obj)
		w.Header().Set("ETag", obj.ETag)
		for name := range obj.Headers {
			if strings.HasPrefix(name, "X-Amz-Checksum-") {
				w.Header().Set(name, obj.Headers.Get(name))
			}
		}
		w.WriteHeader(200)
	case http.MethodGet, http.MethodHead:
		s.store.mu.RLock()
		s.store.versionMu.RLock()
		file, obj, err := s.store.openVersion(dir, digest(key), version)
		s.store.versionMu.RUnlock()
		s.store.mu.RUnlock()
		if err != nil {
			if _, bucketErr := os.Stat(dir); errors.Is(bucketErr, os.ErrNotExist) {
				storageError(w, bucketErr, "NoSuchBucket")
			} else if version != "" {
				storageError(w, err, "NoSuchVersion")
			} else {
				storageError(w, err, "NoSuchKey")
			}
			return
		}
		defer file.Close()
		setVersionHeaders(w, obj)
		if obj.DeleteMarker {
			if version != "" {
				w.Header().Set("Last-Modified", obj.Modified.Format(http.TimeFormat))
				failure(w, 405, "MethodNotAllowed")
			} else {
				failure(w, 404, "NoSuchKey")
			}
			return
		}
		data, err := s.store.objectData(file, obj)
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
		}
		defer data.Close()
		for name, values := range obj.Headers {
			if !strings.HasPrefix(name, "X-Amz-Checksum-") || r.Header.Get("X-Amz-Checksum-Mode") == "ENABLED" && r.Header.Get("Range") == "" {
				w.Header()[name] = values
			}
		}
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", contentType(obj.Headers))
		setEncryptionHeader(w, obj)
		if obj.Protection != nil {
			if s.allows(c, "s3:GetObjectRetention", bucket, key, nil) && !obj.Protection.Retention.Until.IsZero() {
				w.Header().Set("X-Amz-Object-Lock-Mode", obj.Protection.Retention.Mode)
				w.Header().Set("X-Amz-Object-Lock-Retain-Until-Date", obj.Protection.Retention.Until.Format(time.RFC3339Nano))
			}
			if s.allows(c, "s3:GetObjectLegalHold", bucket, key, nil) {
				hold := "OFF"
				if obj.Protection.LegalHold {
					hold = "ON"
				}
				w.Header().Set("X-Amz-Object-Lock-Legal-Hold", hold)
			}
		}
		http.ServeContent(w, r, key, obj.Modified, io.NewSectionReader(data, 0, obj.Size))
	case http.MethodDelete:
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
		if _, err := os.Stat(dir); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		obj, err := s.store.removeVersion(dir, key, version, s.bypassGovernance(r, c, bucket, key))
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
		}
		setVersionHeaders(w, obj)
		w.WriteHeader(204)
	default:
		failure(w, 501, "NotImplemented")
	}
}

func contentType(h http.Header) string {
	if value := h.Get("Content-Type"); value != "" {
		return value
	}
	return "application/octet-stream"
}

type listItem struct {
	Key          string
	LastModified string
	ETag         string
	Size         int64
	StorageClass string
}

func (s *server) listObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	q.Del("x-id")
	for key := range q {
		if !slices.Contains([]string{"list-type", "prefix", "delimiter", "max-keys", "start-after", "continuation-token", "encoding-type"}, key) {
			failure(w, 501, "NotImplemented")
			return
		}
	}
	prefix, delimiter, start := q.Get("prefix"), q.Get("delimiter"), q.Get("start-after")
	token, encoding := q.Get("continuation-token"), q.Get("encoding-type")
	if encoding != "" && encoding != "url" {
		failure(w, 400, "InvalidArgument")
		return
	}
	maxKeys := 1000
	if q.Has("max-keys") {
		n, err := strconv.Atoi(q.Get("max-keys"))
		if err != nil || n < 0 {
			failure(w, 400, "InvalidArgument")
			return
		}
		maxKeys = min(n, maxKeys)
	}
	if token != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(decoded) == 0 {
			failure(w, 400, "InvalidArgument")
			return
		}
		start = string(decoded)
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
	items := map[string]*object{}
	for _, name := range names {
		file, obj, err := s.store.openVersion(dir, name, "")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
		}
		file.Close()
		if obj.DeleteMarker {
			continue
		}
		suffix, ok := strings.CutPrefix(obj.Key, prefix)
		if !ok {
			continue
		}
		if i := strings.Index(suffix, delimiter); delimiter != "" && i >= 0 {
			items[prefix+suffix[:i+len(delimiter)]] = nil
		} else {
			items[obj.Key] = &obj
		}
	}
	keys := make([]string, 0, len(items))
	for key := range items {
		if key > start {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	type commonPrefix struct{ Prefix string }
	result := struct {
		XMLName                                           xml.Name `xml:"ListBucketResult"`
		XMLNS                                             string   `xml:"xmlns,attr"`
		Name, Prefix, Delimiter, EncodingType, StartAfter string
		MaxKeys, KeyCount                                 int
		IsTruncated                                       bool
		ContinuationToken                                 string `xml:",omitempty"`
		NextContinuationToken                             string `xml:",omitempty"`
		Contents                                          []listItem
		CommonPrefixes                                    []commonPrefix
	}{XMLNS: s3Namespace, Name: bucket, Prefix: prefix, Delimiter: delimiter,
		EncodingType: encoding, StartAfter: q.Get("start-after"), MaxKeys: maxKeys,
		KeyCount: min(maxKeys, len(keys)), ContinuationToken: token}
	if maxKeys > 0 && len(keys) > maxKeys {
		result.IsTruncated = true
		result.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(keys[maxKeys-1]))
	}
	format := func(value string) string {
		if encoding == "url" {
			return sigv4.Encode(value, false)
		}
		return value
	}
	result.Prefix, result.Delimiter, result.StartAfter = format(prefix), format(delimiter), format(result.StartAfter)
	for _, key := range keys[:result.KeyCount] {
		obj := items[key]
		if obj == nil {
			result.CommonPrefixes = append(result.CommonPrefixes, commonPrefix{format(key)})
		} else {
			result.Contents = append(result.Contents, listItem{format(key), obj.Modified.Format(time.RFC3339), obj.ETag, obj.Size, "STANDARD"})
		}
	}
	respond(w, 200, result)
}

func validKey(key string) bool {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) {
		return false
	}
	for _, character := range key {
		if character < 32 && character != '\t' && character != '\n' && character != '\r' ||
			character == 0xfffe || character == 0xffff {
			return false
		}
	}
	return true
}

type deletedObject struct {
	Key                   string
	VersionId             string `xml:",omitempty"`
	DeleteMarker          bool   `xml:",omitempty"`
	DeleteMarkerVersionId string `xml:",omitempty"`
}
type deleteError struct {
	Key, Code, Message string
	VersionId          string `xml:",omitempty"`
}

func (s *server) deleteObjects(w http.ResponseWriter, r *http.Request, bucket string, c credential) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		failure(w, 400, "MalformedXML")
		return
	}
	if !validDeleteChecksum(r, body) {
		failure(w, 400, "BadDigest")
		return
	}
	var request struct {
		XMLName xml.Name                          `xml:"Delete"`
		Objects []struct{ Key, VersionId string } `xml:"Object"`
		Quiet   bool
	}
	if xml.Unmarshal(body, &request) != nil || len(request.Objects) == 0 || len(request.Objects) > 1000 {
		failure(w, 400, "MalformedXML")
		return
	}
	allowed := make([]bool, len(request.Objects))
	anyAllowed := false
	for i, obj := range request.Objects {
		if !validKey(obj.Key) {
			failure(w, 400, "InvalidArgument")
			return
		}
		action := "s3:DeleteObject"
		if obj.VersionId != "" {
			action = "s3:DeleteObjectVersion"
		}
		allowed[i] = s.allows(c, action, bucket, obj.Key, nil)
		anyAllowed = anyAllowed || allowed[i]
	}
	if !anyAllowed {
		failure(w, 403, "AccessDenied")
		return
	}

	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	if _, err := os.Stat(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	result := struct {
		XMLName xml.Name `xml:"DeleteResult"`
		XMLNS   string   `xml:"xmlns,attr"`
		Deleted []deletedObject
		Errors  []deleteError `xml:"Error"`
	}{XMLNS: s3Namespace}
	for i, obj := range request.Objects {
		if !allowed[i] {
			result.Errors = append(result.Errors, deleteError{Key: obj.Key, Code: "AccessDenied", Message: "AccessDenied", VersionId: obj.VersionId})
			continue
		}
		removed, err := s.store.removeVersion(dir, obj.Key, obj.VersionId, s.bypassGovernance(r, c, bucket, obj.Key))
		if err != nil {
			code := "InternalError"
			if errors.Is(err, errObjectProtected) {
				code = "AccessDenied"
			}
			result.Errors = append(result.Errors, deleteError{Key: obj.Key, Code: code, Message: "Object could not be deleted", VersionId: obj.VersionId})
		} else if !request.Quiet {
			item := deletedObject{Key: obj.Key, VersionId: obj.VersionId, DeleteMarker: removed.DeleteMarker}
			if removed.DeleteMarker {
				item.DeleteMarkerVersionId = removed.VersionID
			}
			result.Deleted = append(result.Deleted, item)
		}
	}
	if err := fsutil.SyncDir(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	respond(w, 200, result)
}
