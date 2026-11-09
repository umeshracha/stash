package server

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxObject = 5 * 1024 * 1024 * 1024
const maxMetadata = 64 << 10

var errChecksum = errors.New("object checksum mismatch")
var errTooLarge = errors.New("object exceeds the size limit")

type store struct {
	encryption     *encryptionKeys
	erasure        *erasureStore
	dir            string
	lock           *os.File
	mu             sync.RWMutex
	versionMu      sync.RWMutex
	versionHeadsMu sync.Mutex
	versionHeads   map[string]string
	replicaFeeds   map[string]*replicaFeed
	uploadLocks    [64]sync.RWMutex
}

type object struct {
	Encryption   *encryptedObject  `json:",omitempty"`
	Protection   *objectProtection `json:",omitempty"`
	ErasureID    string            `json:",omitempty"`
	Key          string
	Size         int64
	ETag         string
	Modified     time.Time
	Headers      http.Header
	UploadID     string `json:",omitempty"`
	VersionID    string `json:",omitempty"`
	Sequence     int64  `json:",omitempty"`
	DeleteMarker bool   `json:",omitempty"`
	SHA256       string `json:",omitempty"`
}

func openStore(root string) (*store, error) {
	return openStoreMode(root, true)
}

func openStoreMode(root string, recoverLocal bool) (*store, error) {
	dir := filepath.Join(root, "v1")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	if recoverLocal {
		if err := recoverUploads(dir); err != nil {
			lock.Close()
			return nil, err
		}
	}
	return &store{dir: dir, lock: lock}, nil
}

func (s *store) close() { s.lock.Close() }

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *store) put(bucket, key string, r *http.Request) (object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dir := filepath.Join(s.dir, bucket)
	return s.writeObject(dir, key, r)
}

func (s *store) writeObject(dir, key string, r *http.Request) (object, error) {
	return s.stageObject(dir, key, r, func(file *os.File, obj *object) error {
		obj.Protection = requestedProtection(r)
		return s.publishVersion(file, dir, obj)
	})
}

func (s *store) stageObject(dir, key string, r *http.Request, publish func(*os.File, *object) error) (object, error) {
	if r.ContentLength > maxObject {
		return object{}, errTooLarge
	}
	file, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return object{}, err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	md5Hash, shaHash, checksums := objectHashes(r.Header)
	algorithm, _ := r.Context().Value(checksumContext{}).(string)
	computedHeader := ""
	if algorithm != "" {
		computedHeader = checksumHeader(algorithm)
		if checksums[computedHeader] == nil {
			checksums[computedHeader] = checksumHasher(algorithm)
		}
	}
	out, finish, err := s.stagingWriter(file, key)
	if err != nil {
		return object{}, err
	}
	writers := []io.Writer{out}
	for _, checksum := range checksums {
		writers = append(writers, checksum)
	}

	size, err := io.Copy(io.MultiWriter(writers...), io.LimitReader(r.Body, maxObject+1))
	if err != nil {
		return object{}, err
	}
	if size > maxObject {
		return object{}, errTooLarge
	}
	if value := r.Header.Get("X-Amz-Content-Sha256"); value != "UNSIGNED-PAYLOAD" && value != hex.EncodeToString(shaHash.Sum(nil)) {
		return object{}, errChecksum
	}
	metadata := object{Key: key, Size: size, ETag: `"` + hex.EncodeToString(md5Hash.Sum(nil)) + `"`, Modified: time.Now().UTC(), Headers: http.Header{}, SHA256: hex.EncodeToString(shaHash.Sum(nil))}
	for name, checksum := range checksums {
		if name == computedHeader {
			metadata.Headers.Set(name, base64.StdEncoding.EncodeToString(checksum.Sum(nil)))
		}
		if value := r.Header.Get(name); value != "" {
			if value != base64.StdEncoding.EncodeToString(checksum.Sum(nil)) {
				return object{}, errChecksum
			}
			if strings.HasPrefix(name, "X-Amz-") {
				metadata.Headers.Set(name, value)
			}
		}
	}
	// The streaming decoder publishes its verified checksum after consuming the body.
	if stream, ok := r.Context().Value(streamingTrailerContext{}).(*chunkReader); ok {
		metadata.Headers.Set(stream.trailerName, stream.trailerValue)
	}
	for name, values := range uploadHeaders(r.Header) {
		metadata.Headers[name] = values
	}
	metadata.Encryption, err = finish()
	if err != nil {
		return object{}, err
	}
	err = publish(file, &metadata)
	return metadata, err
}

func uploadHeaders(headers http.Header) http.Header {
	result := http.Header{}
	for name, values := range headers {
		if strings.HasPrefix(name, "X-Amz-Meta-") || name == "Content-Type" || name == "Content-Encoding" || name == "Cache-Control" || name == "Content-Disposition" {
			result[name] = values
		}
	}
	return result
}

func commitObject(file *os.File, dir, name string, metadata object) error {
	body, err := json.Marshal(metadata)
	if err != nil || len(body) > maxMetadata {
		return errTooLarge
	}
	footer := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	if _, err := file.Write(append(body, footer...)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

func readMetadata(file *os.File) (object, error) {
	invalid := errors.New("invalid object metadata")
	var value object
	info, err := file.Stat()
	if err != nil {
		return value, err
	}
	var footer [4]byte
	if _, err := file.ReadAt(footer[:], info.Size()-4); err != nil {
		return value, err
	}
	length := int64(binary.BigEndian.Uint32(footer[:]))
	offset := info.Size() - 4 - length
	if length > maxMetadata || offset < 0 {
		return value, invalid
	}
	body := make([]byte, length)
	if _, err := file.ReadAt(body, offset); err != nil {
		return value, err
	}
	if err := json.Unmarshal(body, &value); err != nil || value.Size < 0 || value.Size > maxMultipartSize ||
		value.ErasureID == "" && value.payloadSize() != offset || value.ErasureID != "" && offset != 0 {
		return value, invalid
	}
	return value, nil
}

func objectHashes(headers http.Header) (hash.Hash, hash.Hash, map[string]hash.Hash) {
	md5Hash, shaHash := md5.New(), sha256.New()
	checksums := map[string]hash.Hash{"Content-Md5": md5Hash, "X-Amz-Checksum-Sha256": shaHash}
	if headers.Get("X-Amz-Checksum-Sha1") != "" {
		checksums["X-Amz-Checksum-Sha1"] = sha1.New()
	}
	for name, polynomial := range map[string]uint32{"X-Amz-Checksum-Crc32": crc32.IEEE, "X-Amz-Checksum-Crc32c": crc32.Castagnoli} {
		if headers.Get(name) != "" {
			checksums[name] = crc32.New(crc32.MakeTable(polynomial))
		}
	}
	if name := "X-Amz-Checksum-Crc64nvme"; headers.Get(name) != "" {
		checksums[name] = crc64.New(nvmeTable)
	}
	return md5Hash, shaHash, checksums
}

func validDeleteChecksum(r *http.Request, body []byte) bool {
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload != "UNSIGNED-PAYLOAD" && payload != digest(string(body)) {
		return false
	}
	_, _, checksums := objectHashes(r.Header)
	verified := false
	for name, checksum := range checksums {
		if value := r.Header.Get(name); value != "" {
			checksum.Write(body)
			if value != base64.StdEncoding.EncodeToString(checksum.Sum(nil)) {
				return false
			}
			verified = true
		}
	}
	return verified
}
