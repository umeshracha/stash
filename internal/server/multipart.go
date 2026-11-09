package server

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"stash/internal/fsutil"
	"stash/internal/sigv4"
	"stash/internal/upload"
)

const (
	maxParts               = 10000
	minPartSize            = 5 << 20
	maxMultipartSize int64 = 5 << 40
)

type uploadInfo struct {
	Checksum   upload.Checksum   `json:",omitempty"`
	Created    time.Time         `json:",omitempty"`
	Protection *objectProtection `json:",omitempty"`
	Key        string
	Headers    http.Header
}

func (s *server) multipart(w http.ResponseWriter, r *http.Request, bucket, key string, q url.Values, c credential) {
	for _, values := range q {
		if len(values) != 1 {
			failure(w, 400, "InvalidArgument")
			return
		}
	}
	dir := filepath.Join(s.store.dir, bucket)
	if r.Method == http.MethodPost && q.Has("uploadId") {
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
	} else {
		s.store.mu.RLock()
		defer s.store.mu.RUnlock()
	}
	if _, err := os.Stat(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	if q.Has("uploads") && len(q) == 1 && r.Method == http.MethodPost {
		startUpload(w, r, dir, bucket, key, s.store.encryption != nil)
		return
	}
	id := q.Get("uploadId")
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || id != strings.ToLower(id) {
		failure(w, 404, "NoSuchUpload")
		return
	}
	lock := &s.store.uploadLocks[int(decoded[0])%len(s.store.uploadLocks)]
	if r.Method == http.MethodPut {
		lock.RLock()
		defer lock.RUnlock()
	} else {
		lock.Lock()
		defer lock.Unlock()
	}
	stage := filepath.Join(dir, ".mp-"+id)
	var info uploadInfo
	raw, err := os.ReadFile(filepath.Join(stage, "upload.json"))
	if err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	if json.Unmarshal(raw, &info) != nil {
		failure(w, 500, "InternalError")
		return
	}
	if info.Key != key {
		failure(w, 404, "NoSuchUpload")
		return
	}
	if r.Header.Get("X-Amz-Copy-Source") != "" && r.Method != http.MethodPut {
		failure(w, 400, "InvalidRequest")
		return
	}
	switch r.Method {
	case http.MethodPut:
		number, err := strconv.Atoi(q.Get("partNumber"))
		if len(q) != 2 || err != nil || number < 1 || number > maxParts {
			failure(w, 400, "InvalidArgument")
			return
		}
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			s.copyPart(w, r, c, stage, key, number, info.Checksum)
			return
		}
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			failure(w, 501, "NotImplemented")
			return
		}
		if !upload.ValidatePart(r, info.Checksum) {
			failure(w, 400, "InvalidRequest")
			return
		}
		part, err := s.store.stageObject(stage, key, upload.Compute(r, info.Checksum.Algorithm), func(file *os.File, obj *object) error {
			return s.store.commitData(file, stage, partName(number), obj)
		})
		if err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		w.Header().Set("ETag", part.ETag)
		for name := range part.Headers {
			if strings.HasPrefix(name, "X-Amz-Checksum-") {
				w.Header().Set(name, part.Headers.Get(name))
			}
		}
		w.WriteHeader(200)
	case http.MethodGet:
		listParts(w, q, stage, bucket, key, id, info.Checksum)
	case http.MethodPost:
		if len(q) != 1 {
			failure(w, 400, "InvalidArgument")
			return
		}
		s.store.completeUpload(w, r, dir, stage, bucket, id, info)
	case http.MethodDelete:
		if len(q) != 1 {
			failure(w, 400, "InvalidArgument")
			return
		}
		if err := discardUpload(dir, stage); err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		w.WriteHeader(204)
	default:
		failure(w, 501, "NotImplemented")
	}
}

func startUpload(w http.ResponseWriter, r *http.Request, dir, bucket, key string, encrypted bool) {
	if requestedProtection(r) != nil {
		config, err := readLockConfig(dir)
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		if config == nil {
			failure(w, 400, "InvalidRequest")
			return
		}
	}
	checksum, valid := upload.Resolve(r.Header.Get("X-Amz-Checksum-Algorithm"), r.Header.Get(upload.TypeHeader))
	if !valid {
		failure(w, 400, "InvalidRequest")
		return
	}

	var entropy [16]byte
	rand.Read(entropy[:])
	id := hex.EncodeToString(entropy[:])
	// Publish the directory only after its manifest is durable.
	tmp, err := os.MkdirTemp(dir, ".start-mp-")
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	defer os.RemoveAll(tmp)
	raw, err := json.Marshal(uploadInfo{Key: key, Headers: uploadHeaders(r.Header), Protection: requestedProtection(r), Created: time.Now().UTC(), Checksum: checksum})
	if err != nil || len(raw) > maxMetadata {
		failure(w, 400, "MetadataTooLarge")
		return
	}
	manifest, err := os.OpenFile(filepath.Join(tmp, "upload.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	_, writeErr := manifest.Write(raw)
	err = errors.Join(writeErr, manifest.Sync(), manifest.Close())
	if err == nil {
		err = fsutil.SyncDir(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, ".mp-"+id))
	}
	if err == nil {
		err = fsutil.SyncDir(dir)
	}
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	if encrypted {
		w.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
	}
	if checksum.Algorithm != "" {
		w.Header().Set("X-Amz-Checksum-Algorithm", checksum.Algorithm)
		w.Header().Set(upload.TypeHeader, checksum.Type)
	}
	respond(w, 200, struct {
		XMLName               xml.Name `xml:"InitiateMultipartUploadResult"`
		XMLNS                 string   `xml:"xmlns,attr"`
		Bucket, Key, UploadId string
	}{XMLNS: s3Namespace, Bucket: bucket, Key: key, UploadId: id})
}

func partName(number int) string { return fmt.Sprintf("part-%05d", number) }

type listedPart struct {
	PartNumber   int
	LastModified string
	ETag         string
	Size         int64
	upload.Fields
}

func listParts(w http.ResponseWriter, q url.Values, stage, bucket, key, id string, checksum upload.Checksum) {
	for name := range q {
		if name != "uploadId" && name != "max-parts" && name != "part-number-marker" {
			failure(w, 400, "InvalidArgument")
			return
		}
	}
	marker, count := 0, 1000
	for name, target := range map[string]*int{"part-number-marker": &marker, "max-parts": &count} {
		if q.Has(name) {
			n, err := strconv.Atoi(q.Get(name))
			if err != nil || n < 0 {
				failure(w, 400, "InvalidArgument")
				return
			}
			*target = n
		}
	}
	count = min(count, 1000)
	entries, err := os.ReadDir(stage)
	if err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	result := struct {
		XMLName                             xml.Name `xml:"ListPartsResult"`
		XMLNS                               string   `xml:"xmlns,attr"`
		Bucket, Key, UploadId, StorageClass string
		ChecksumAlgorithm, ChecksumType     string `xml:",omitempty"`

		PartNumberMarker, NextPartNumberMarker, MaxParts int
		IsTruncated                                      bool
		Parts                                            []listedPart `xml:"Part"`
	}{XMLNS: s3Namespace, Bucket: bucket, Key: key, UploadId: id, StorageClass: "STANDARD", ChecksumAlgorithm: checksum.Algorithm, ChecksumType: checksum.Type, PartNumberMarker: marker, MaxParts: count}
	for _, entry := range entries {
		suffix, ok := strings.CutPrefix(entry.Name(), "part-")
		if !ok {
			continue
		}
		number, err := strconv.Atoi(suffix)
		if err != nil || number <= marker {
			continue
		}
		if len(result.Parts) == count {
			result.IsTruncated = count > 0
			break
		}
		file, err := os.Open(filepath.Join(stage, entry.Name()))
		if err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		part, err := readMetadata(file)
		file.Close()
		if err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		result.Parts = append(result.Parts, listedPart{
			PartNumber: number, LastModified: part.Modified.Format(time.RFC3339), ETag: part.ETag,
			Size: part.Size, Fields: upload.Values(part.Headers),
		})

		result.NextPartNumberMarker = number
	}
	respond(w, 200, result)
}

func discardUpload(dir, stage string) error {
	trash := filepath.Join(dir, ".upload-"+filepath.Base(stage))
	if err := os.Rename(stage, trash); err != nil {
		return err
	}
	if err := fsutil.SyncDir(dir); err != nil {
		return err
	}
	if err := os.RemoveAll(trash); err != nil {
		log.Printf("cleanup of multipart staging failed: %v", err)
	}
	return nil
}

func (s *store) completeUpload(w http.ResponseWriter, r *http.Request, dir, stage, bucket, id string, info uploadInfo) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		failure(w, 400, "MalformedXML")
		return
	}
	if payload := r.Header.Get("X-Amz-Content-Sha256"); payload != "UNSIGNED-PAYLOAD" && payload != digest(string(body)) {
		failure(w, 400, "BadDigest")
		return
	}
	if !upload.ValidateCompletion(r, info.Checksum) {
		failure(w, 400, "InvalidRequest")
		return
	}

	var request struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []struct {
			PartNumber int
			ETag       string
			upload.Fields
		} `xml:"Part"`
	}
	if xml.Unmarshal(body, &request) != nil || len(request.Parts) == 0 || len(request.Parts) > maxParts {
		failure(w, 400, "MalformedXML")
		return
	}
	previous := 0
	for i, part := range request.Parts {
		if part.PartNumber <= previous || part.PartNumber > maxParts || info.Checksum.Type == upload.Composite && part.PartNumber != i+1 {
			failure(w, 400, "InvalidPartOrder")
			return
		}
		previous = part.PartNumber
	}
	name := digest(info.Key)
	if saved, err := completedUploadVersion(dir, name, id); err == nil && saved.UploadID == id {
		if err := discardUpload(dir, stage); err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		multipartResult(w, bucket, saved)
		return
	}
	file, err := os.CreateTemp(dir, ".upload-")
	if err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	defer os.Remove(file.Name())
	defer file.Close()
	out, finish, err := s.stagingWriter(file, info.Key)
	if err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	combined := md5.New()
	contentHash := sha256.New()
	finalChecksum := upload.Hasher(info.Checksum.Algorithm)
	if info.Headers == nil {
		info.Headers = make(http.Header)
	}
	obj := object{Key: info.Key, Modified: time.Now().UTC(), Headers: info.Headers, UploadID: id, Protection: info.Protection}
	for i, requested := range request.Parts {
		partFile, err := os.Open(filepath.Join(stage, partName(requested.PartNumber)))
		if errors.Is(err, os.ErrNotExist) {
			failure(w, 400, "InvalidPart")
			return
		}
		if err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		part, err := readMetadata(partFile)
		if err != nil {
			partFile.Close()
			storageError(w, err, "NoSuchUpload")
			return
		}
		if strings.Trim(requested.ETag, `"`) != strings.Trim(part.ETag, `"`) ||
			!requested.Fields.Matches(part.Headers) {
			partFile.Close()
			failure(w, 400, "InvalidPart")
			return
		}
		if i != len(request.Parts)-1 && part.Size < minPartSize {
			partFile.Close()
			failure(w, 400, "EntityTooSmall")
			return
		}
		if part.Size > maxMultipartSize-obj.Size {
			partFile.Close()
			failure(w, 413, "EntityTooLarge")
			return
		}

		data, err := s.objectData(partFile, part)
		if err != nil {
			storageError(w, err, "NoSuchUpload")
			return
		}
		check := md5.New()
		writers := []io.Writer{out, check, contentHash}
		partChecksum := upload.Hasher(info.Checksum.Algorithm)
		if partChecksum != nil {
			writers = append(writers, partChecksum)
			if info.Checksum.Type == upload.Full {
				writers = append(writers, finalChecksum)
			}
		}
		n, err := io.Copy(io.MultiWriter(writers...), io.NewSectionReader(data, 0, part.Size))
		data.Close()
		if err != nil || n != part.Size || hex.EncodeToString(check.Sum(nil)) != strings.Trim(part.ETag, `"`) {
			failure(w, 500, "InternalError")
			return
		}
		if partChecksum != nil {
			raw := partChecksum.Sum(nil)
			if part.Headers.Get(upload.Header(info.Checksum.Algorithm)) != base64.StdEncoding.EncodeToString(raw) {
				failure(w, 400, "InvalidPart")
				return
			}
			if info.Checksum.Type == upload.Composite {
				finalChecksum.Write(raw)
			}
		}
		combined.Write(check.Sum(nil))
		obj.Size += n
	}
	if value := r.Header.Get("X-Amz-Mp-Object-Size"); value != "" {
		size, err := strconv.ParseInt(value, 10, 64)
		if err != nil || size != obj.Size {
			failure(w, 400, "InvalidRequest")
			return
		}
	}
	if finalChecksum != nil {
		name := upload.Header(info.Checksum.Algorithm)
		value := upload.Completed(finalChecksum, info.Checksum.Type, len(request.Parts))
		if expected := r.Header.Get(name); expected != "" && expected != value {
			failure(w, 400, "BadDigest")
			return
		}
		obj.Headers.Set(name, value)
		obj.Headers.Set(upload.TypeHeader, info.Checksum.Type)
	}
	obj.Encryption, err = finish()
	if err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	obj.SHA256 = hex.EncodeToString(contentHash.Sum(nil))
	obj.ETag = fmt.Sprintf("\"%x-%d\"", combined.Sum(nil), len(request.Parts))
	if err := s.publishVersion(file, dir, &obj); err != nil {
		storageError(w, err, "NoSuchUpload")
		return
	}
	if err := discardUpload(dir, stage); err != nil {
		log.Printf("cleanup of completed multipart upload failed: %v", err)
	}
	multipartResult(w, bucket, obj)
}

func multipartResult(w http.ResponseWriter, bucket string, obj object) {
	setVersionHeaders(w, obj)
	setEncryptionHeader(w, obj)
	respond(w, 200, struct {
		XMLName                     xml.Name `xml:"CompleteMultipartUploadResult"`
		XMLNS                       string   `xml:"xmlns,attr"`
		Location, Bucket, Key, ETag string
		ChecksumType                string `xml:",omitempty"`
		upload.Fields
	}{XMLNS: s3Namespace, Location: "/" + bucket + "/" + sigv4.Encode(obj.Key, true), Bucket: bucket, Key: obj.Key, ETag: obj.ETag,
		ChecksumType: obj.Headers.Get(upload.TypeHeader), Fields: upload.Values(obj.Headers)})

}

func metadataAt(path string) (object, error) {
	file, err := os.Open(path)
	if err != nil {
		return object{}, err
	}
	defer file.Close()
	return readMetadata(file)
}

func recoverUploads(root string) error {
	buckets, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, bucket := range buckets {
		if !bucket.IsDir() || !bucketName.MatchString(bucket.Name()) {
			continue
		}
		dir := filepath.Join(root, bucket.Name())
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			switch {
			case strings.HasPrefix(entry.Name(), ".upload-"), strings.HasPrefix(entry.Name(), ".start-mp-"):
				if err := os.RemoveAll(path); err != nil {
					return err
				}
			case strings.HasPrefix(entry.Name(), ".mp-"):
				raw, err := os.ReadFile(filepath.Join(path, "upload.json"))
				if err != nil {
					return err
				}
				var info uploadInfo
				if err := json.Unmarshal(raw, &info); err != nil {
					return err
				}
				obj, err := completedUploadVersion(dir, digest(info.Key), strings.TrimPrefix(entry.Name(), ".mp-"))
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if obj.UploadID == strings.TrimPrefix(entry.Name(), ".mp-") {
					if err := discardUpload(dir, path); err != nil {
						return err
					}
				}
				parts, err := os.ReadDir(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				for _, part := range parts {
					if strings.HasPrefix(part.Name(), ".upload-") {
						if err := os.Remove(filepath.Join(path, part.Name())); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func completedUploadVersion(dir, name, id string) (object, error) {
	versions, err := versionsFor(dir, name)
	if err != nil {
		return object{}, err
	}
	for _, version := range versions {
		if version.UploadID == id {
			obj := version.object
			if obj.VersionID == "null" && obj.Sequence == 0 {
				obj.VersionID = ""
			}
			return obj, nil
		}
	}
	return object{}, os.ErrNotExist
}

func decodeUploadInfo(data []byte) (uploadInfo, error) {
	var info uploadInfo
	err := json.Unmarshal(data, &info)
	return info, err
}
