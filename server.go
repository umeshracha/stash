package main

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
)

type server struct {
	store       *store
	credentials map[string]credential
	region      string
}

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	xml.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, code string) {
	respond(w, status, struct {
		XMLName xml.Name `xml:"Error"`
		Code    string
		Message string
	}{Code: code, Message: code})
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
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	c, ok := s.authorize(r)
	if !ok {
		failure(w, 403, "AccessDenied")
		return
	}
	w.Header().Set("X-Amz-Bucket-Region", s.region)
	if r.URL.Path == "/" && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		s.listBuckets(w, c)
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !bucketName.MatchString(bucket) || key != "" && !validKey(key) {
		failure(w, 400, "InvalidArgument")
		return
	}
	permission := c.permission(bucket)
	if permission == "" || r.Method != http.MethodGet && r.Method != http.MethodHead && permission == "read" ||
		key == "" && (r.Method == http.MethodPut || r.Method == http.MethodDelete) && permission != "admin" {
		failure(w, 403, "AccessDenied")
		return
	}

	query := r.URL.Query()
	if key == "" {
		switch {
		case r.URL.RawQuery == "":
			s.bucket(w, r, bucket)
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
		case r.Method == http.MethodPost && len(query) == 1 && query.Has("delete"):
			s.deleteObjects(w, r, bucket)
		case r.Method == http.MethodGet && query.Get("list-type") == "2":
			s.listObjects(w, r, bucket)
		default:
			failure(w, 501, "NotImplemented")
		}
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("X-Amz-Copy-Source") != "" ||
		r.Header.Get("X-Amz-Server-Side-Encryption") != "" || r.Header.Get("X-Amz-Tagging") != "" ||
		r.Method == http.MethodPut && (r.Header.Get("If-Match") != "" || r.Header.Get("If-None-Match") != "") {
		failure(w, 501, "NotImplemented")
		return
	}
	s.object(w, r, bucket, key)
}

func storageError(w http.ResponseWriter, err error, missing string) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		failure(w, 404, missing)
	case errors.Is(err, errChecksum):
		failure(w, 400, "BadDigest")
	case errors.Is(err, errTooLarge):
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
		if !entry.IsDir() || c.permission(entry.Name()) == "" {
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

func (s *server) bucket(w http.ResponseWriter, r *http.Request, bucket string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	path := filepath.Join(s.store.dir, bucket)
	switch r.Method {
	case http.MethodPut:
		if r.ContentLength != 0 {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
			var request struct{ LocationConstraint string }
			if err != nil || digest(string(body)) != r.Header.Get("X-Amz-Content-Sha256") ||
				xml.Unmarshal(body, &request) != nil || request.LocationConstraint != s.region {
				failure(w, 400, "InvalidLocationConstraint")
				return
			}
		}
		if err := os.Mkdir(path, 0700); err != nil {
			if errors.Is(err, os.ErrExist) {
				failure(w, 409, "BucketAlreadyOwnedByYou")
			} else {
				storageError(w, err, "NoSuchBucket")
			}
			return
		}
		if err := syncDir(s.store.dir); err != nil {
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
			if !strings.HasPrefix(entry.Name(), ".upload-") {
				failure(w, 409, "BucketNotEmpty")
				return
			}
			if err := os.Remove(filepath.Join(path, entry.Name())); err != nil {
				storageError(w, err, "NoSuchBucket")
				return
			}
		}
		if err := os.Remove(path); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		if err := syncDir(s.store.dir); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(204)
	default:
		failure(w, 501, "NotImplemented")
	}
}

func (s *server) object(w http.ResponseWriter, r *http.Request, bucket, key string) {
	dir := filepath.Join(s.store.dir, bucket)
	path := filepath.Join(dir, digest(key))
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
		w.Header().Set("ETag", obj.ETag)
		for name := range obj.Headers {
			if strings.HasPrefix(name, "X-Amz-Checksum-") {
				w.Header().Set(name, obj.Headers.Get(name))
			}
		}
		w.WriteHeader(200)
	case http.MethodGet, http.MethodHead:
		file, err := os.Open(path)
		if err != nil {
			if _, bucketErr := os.Stat(dir); errors.Is(bucketErr, os.ErrNotExist) {
				storageError(w, bucketErr, "NoSuchBucket")
			} else {
				storageError(w, err, "NoSuchKey")
			}
			return
		}
		defer file.Close()
		obj, err := readMetadata(file)
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
		}
		for name, values := range obj.Headers {
			if !strings.HasPrefix(name, "X-Amz-Checksum-") || r.Header.Get("X-Amz-Checksum-Mode") == "ENABLED" && r.Header.Get("Range") == "" {
				w.Header()[name] = values
			}
		}
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", contentType(obj.Headers))
		http.ServeContent(w, r, key, obj.Modified, io.NewSectionReader(file, 0, obj.Size))
	case http.MethodDelete:
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
		if _, err := os.Stat(dir); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			storageError(w, err, "NoSuchKey")
			return
		}
		if err := syncDir(dir); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	items := map[string]*object{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		file, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
		}
		obj, err := readMetadata(file)
		file.Close()
		if err != nil {
			storageError(w, err, "NoSuchKey")
			return
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
			return encode(value, false)
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

type deletedObject struct{ Key string }
type deleteError struct{ Key, Code, Message string }

func (s *server) deleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
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
	for _, obj := range request.Objects {
		if !validKey(obj.Key) || obj.VersionId != "" {
			failure(w, 400, "InvalidArgument")
			return
		}
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
	for _, obj := range request.Objects {
		err := os.Remove(filepath.Join(dir, digest(obj.Key)))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			result.Errors = append(result.Errors, deleteError{obj.Key, "InternalError", "Object could not be deleted"})
		} else if !request.Quiet {
			result.Deleted = append(result.Deleted, deletedObject{obj.Key})
		}
	}
	if err := syncDir(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	respond(w, 200, result)
}
