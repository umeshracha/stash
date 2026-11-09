package server

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"stash/internal/upload"
)

func (s *server) copyObject(w http.ResponseWriter, r *http.Request, c credential, bucket, key string) {
	if r.Header.Get("X-Amz-Copy-Source-Range") != "" {
		failure(w, 400, "InvalidArgument")
		return
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	source, obj, location, ok := s.openCopySource(w, r, c)
	if !ok {
		return
	}
	defer source.Close()
	directive := r.Header.Get("X-Amz-Metadata-Directive")
	switch directive {
	case "", "COPY":
		if location.bucket == bucket && location.key == key && location.version == "" {
			failure(w, 400, "InvalidRequest")
			return
		}
	case "REPLACE":
	default:
		failure(w, 400, "InvalidArgument")
		return
	}
	copyRequest := r.Clone(r.Context())
	copyRequest.Body = io.NopCloser(io.NewSectionReader(source, 0, obj.Size))
	copyRequest.ContentLength = obj.Size
	copyRequest.Header = uploadHeaders(obj.Headers)
	if directive == "REPLACE" {
		copyRequest.Header = uploadHeaders(r.Header)
	}
	algorithm := r.Header.Get("X-Amz-Checksum-Algorithm")
	if algorithm != "" && upload.Hasher(algorithm) == nil {
		failure(w, 400, "InvalidRequest")
		return
	}
	if algorithm == "" {
		for _, candidate := range []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"} {
			if obj.Headers.Get(upload.Header(candidate)) != "" {
				algorithm = candidate
				break
			}
		}
	}
	payloadHash := obj.SHA256
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	copyRequest.Header.Set("X-Amz-Content-Sha256", payloadHash)
	copyRequest = upload.Compute(copyRequest, algorithm)

	result, err := s.store.writeObject(filepath.Join(s.store.dir, bucket), key, copyRequest)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	if obj.VersionID != "" {
		w.Header().Set("X-Amz-Copy-Source-Version-Id", obj.VersionID)
	}
	setVersionHeaders(w, result)
	setEncryptionHeader(w, result)
	respond(w, 200, struct {
		XMLName            xml.Name `xml:"CopyObjectResult"`
		XMLNS              string   `xml:"xmlns,attr"`
		LastModified, ETag string
		upload.Fields
	}{XMLNS: s3Namespace, LastModified: result.Modified.Format(time.RFC3339Nano), ETag: result.ETag, Fields: upload.Values(result.Headers)})
}

type copyLocation struct{ bucket, key, version string }

// The caller holds the store lock while resolving and copying the source.
func (s *server) openCopySource(w http.ResponseWriter, r *http.Request, c credential) (objectReader, object, copyLocation, bool) {
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-copy-source-server-side-") ||
			lower == "x-amz-tagging-directive" {
			failure(w, 501, "NotImplemented")
			return nil, object{}, copyLocation{}, false
		}
	}
	if r.ContentLength != 0 {
		failure(w, 400, "InvalidRequest")
		return nil, object{}, copyLocation{}, false
	}
	raw := r.Header.Get("X-Amz-Copy-Source")
	rawPath, rawQuery, hasQuery := strings.Cut(raw, "?")
	version := ""
	if hasQuery {
		query, err := url.ParseQuery(rawQuery)
		if err != nil || len(query) != 1 || len(query["versionId"]) != 1 || query.Get("versionId") == "" {
			failure(w, 400, "InvalidArgument")
			return nil, object{}, copyLocation{}, false
		}
		version = query.Get("versionId")
	}
	path, err := url.PathUnescape(rawPath)
	sourceBucket, sourceKey, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if err != nil || !bucketName.MatchString(sourceBucket) || !validKey(sourceKey) {
		failure(w, 400, "InvalidArgument")
		return nil, object{}, copyLocation{}, false
	}
	sourceAction := "s3:GetObject"
	if version != "" {
		sourceAction = "s3:GetObjectVersion"
	}
	if !s.allows(c, sourceAction, sourceBucket, sourceKey, nil) {
		failure(w, 403, "AccessDenied")
		return nil, object{}, copyLocation{}, false
	}
	sourceDir := filepath.Join(s.store.dir, sourceBucket)
	s.store.versionMu.RLock()
	source, obj, err := s.store.openVersion(sourceDir, digest(sourceKey), version)
	s.store.versionMu.RUnlock()
	if err != nil {
		if _, statErr := os.Stat(sourceDir); errors.Is(statErr, os.ErrNotExist) {
			storageError(w, statErr, "NoSuchBucket")
		} else if version != "" {
			storageError(w, err, "NoSuchVersion")
		} else {
			storageError(w, err, "NoSuchKey")
		}
		return nil, object{}, copyLocation{}, false
	}
	if obj.DeleteMarker {
		source.Close()
		if version != "" {
			failure(w, 400, "InvalidRequest")
		} else {
			failure(w, 404, "NoSuchKey")
		}
		return nil, object{}, copyLocation{}, false
	}

	if !copyPreconditions(w, r, obj) {
		source.Close()
		return nil, object{}, copyLocation{}, false
	}
	data, err := s.store.objectData(source, obj)
	if err != nil {
		storageError(w, err, "NoSuchKey")
		return nil, object{}, copyLocation{}, false
	}
	return data, obj, copyLocation{sourceBucket, sourceKey, version}, true
}

func copyPreconditions(w http.ResponseWriter, r *http.Request, obj object) bool {
	match := r.Header.Get("X-Amz-Copy-Source-If-Match")
	notMatch := r.Header.Get("X-Amz-Copy-Source-If-None-Match")
	etagMatches := func(value string) bool { return value == "*" || value == obj.ETag }
	if match != "" && !etagMatches(match) || notMatch != "" && etagMatches(notMatch) {
		failure(w, 412, "PreconditionFailed")
		return false
	}
	modified := obj.Modified.Truncate(time.Second)
	for _, condition := range []struct {
		header            string
		after, overridden bool
	}{
		{"X-Amz-Copy-Source-If-Unmodified-Since", false, match != ""},
		{"X-Amz-Copy-Source-If-Modified-Since", true, notMatch != ""},
	} {
		if condition.overridden {
			continue
		}
		value := r.Header.Get(condition.header)
		if value == "" {
			continue
		}
		at, err := http.ParseTime(value)
		if err != nil {
			failure(w, 400, "InvalidArgument")
			return false
		}
		if modified.After(at) != condition.after {
			failure(w, 412, "PreconditionFailed")
			return false
		}
	}
	return true
}

func copyRange(value string, size int64) (offset, count int64, valid bool) {
	if value == "" {
		return 0, size, true
	}
	raw, ok := strings.CutPrefix(value, "bytes=")
	left, right, found := strings.Cut(raw, "-")
	start, errStart := strconv.ParseInt(left, 10, 64)
	end, errEnd := strconv.ParseInt(right, 10, 64)
	if !ok || !found || errStart != nil || errEnd != nil || start < 0 || end < start || end >= size || size <= minPartSize {
		return 0, 0, false
	}
	return start, end - start + 1, true
}

func (s *server) copyPart(w http.ResponseWriter, r *http.Request, c credential, stage, key string, number int, checksum upload.Checksum) {
	if r.Header.Get("X-Amz-Metadata-Directive") != "" {
		failure(w, 400, "InvalidArgument")
		return
	}
	data, source, _, ok := s.openCopySource(w, r, c)
	if !ok {
		return
	}
	defer data.Close()
	offset, count, valid := copyRange(r.Header.Get("X-Amz-Copy-Source-Range"), source.Size)
	if !valid {
		failure(w, 400, "InvalidArgument")
		return
	}
	copied := r.Clone(r.Context())
	copied.Body = io.NopCloser(io.NewSectionReader(data, offset, count))
	copied.ContentLength = count
	copied.Header = http.Header{"X-Amz-Content-Sha256": {"UNSIGNED-PAYLOAD"}}
	part, err := s.store.stageObject(stage, key, upload.Compute(copied, checksum.Algorithm), func(file *os.File, obj *object) error {
		return s.store.commitData(file, stage, partName(number), obj)
	})
	if err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	if source.VersionID != "" {
		w.Header().Set("X-Amz-Copy-Source-Version-Id", source.VersionID)
	}
	setEncryptionHeader(w, part)
	respond(w, 200, struct {
		XMLName            xml.Name `xml:"CopyPartResult"`
		XMLNS              string   `xml:"xmlns,attr"`
		LastModified, ETag string
		upload.Fields
	}{XMLNS: s3Namespace, LastModified: part.Modified.Format(time.RFC3339Nano), ETag: part.ETag, Fields: upload.Values(part.Headers)})

}
