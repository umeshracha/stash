package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"stash/internal/fsutil"
)

const encryptionBlock = 256 << 10
const encryptionTagSize = 16
const BindingFile = ".encrypted"

var ErrUnavailable = errors.New("object encryption key unavailable")
var ErrCiphertext = errors.New("object ciphertext failed authentication")
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Config struct {
	ActiveKey string            `json:"active_key"`
	KeyFiles  map[string]string `json:"key_files"`
}

type Keys struct {
	active string
	keys   map[string][]byte
}

type Binding struct {
	Version, Active string
	Keys            map[string]string
}

const Version = "AES-256-GCM-v1"

func DecodeBinding(data []byte) (Binding, error) {
	var binding Binding
	if err := json.Unmarshal(data, &binding); err != nil || binding.Version != Version ||
		!keyIDPattern.MatchString(binding.Active) || binding.Keys[binding.Active] == "" ||
		len(binding.Keys) > 100 {
		return Binding{}, errors.New("invalid encryption binding")
	}
	for id, fingerprint := range binding.Keys {
		raw, err := hex.DecodeString(fingerprint)
		if !keyIDPattern.MatchString(id) || err != nil || len(raw) != sha256.Size {
			return Binding{}, errors.New("invalid encryption key fingerprint")
		}
	}
	return binding, nil
}

func (binding Binding) Includes(required Binding) bool {
	for id, fingerprint := range required.Keys {
		if binding.Keys[id] != fingerprint {
			return false
		}
	}
	return true
}

type Metadata struct {
	KeyID string
	Salt  []byte
}

func Open(dir string, cfg *Config) (*Keys, error) {
	previous, err := os.ReadFile(filepath.Join(dir, BindingFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if cfg == nil {
		if err == nil {
			return nil, errors.New("this data directory requires its encryption key configuration")
		}
		return nil, nil
	}
	if !keyIDPattern.MatchString(cfg.ActiveKey) || len(cfg.KeyFiles) == 0 || len(cfg.KeyFiles) > 100 || cfg.KeyFiles[cfg.ActiveKey] == "" {
		return nil, errors.New("configure an active encryption key and its key file")
	}
	result := &Keys{active: cfg.ActiveKey, keys: make(map[string][]byte)}
	for id, path := range cfg.KeyFiles {
		if !keyIDPattern.MatchString(id) {
			return nil, errors.New("invalid encryption key ID")
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open encryption key %q: %w", id, err)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			file.Close()
			return nil, fmt.Errorf("encryption key %q requires a private regular file", id)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 1025))
		file.Close()
		if readErr != nil || len(data) > 1024 {
			return nil, fmt.Errorf("cannot read encryption key %q", id)
		}
		key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
		clear(data)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("encryption key %q must contain 32 base64-encoded bytes", id)
		}
		result.keys[id] = key
	}
	fingerprints := make(map[string]string, len(result.keys))
	for id, key := range result.keys {
		hash := sha256.Sum256(key)
		fingerprints[id] = hex.EncodeToString(hash[:])
	}
	if len(previous) != 0 {
		existing, err := DecodeBinding(previous)
		if err != nil {
			return nil, err
		}
		for id, fingerprint := range existing.Keys {
			if fingerprints[id] != fingerprint {
				return nil, fmt.Errorf("previous encryption key %q is missing or has changed", id)
			}
		}
	}
	binding, err := json.Marshal(Binding{Version, result.active, fingerprints})
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(dir, BindingFile, binding); err != nil {
		return nil, err
	}
	return result, nil
}

func (k *Keys) cipher(info *Metadata) (cipher.AEAD, error) {
	if k == nil || info == nil || len(info.Salt) != 32 {
		return nil, ErrUnavailable
	}
	master, ok := k.keys[info.KeyID]
	if !ok {
		return nil, ErrUnavailable
	}
	key, err := hkdf.Key(sha256.New, master, info.Salt, "stash object encryption v1", 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type encryptWriter struct {
	out    io.Writer
	aead   cipher.AEAD
	info   *Metadata
	buf    []byte
	sealed []byte
	index  uint64
	aad    []byte
}

func (k *Keys) Writer(file io.Writer, key string) (io.Writer, func() (*Metadata, error), error) {
	if k == nil {
		return file, func() (*Metadata, error) { return nil, nil }, nil
	}
	salt := make([]byte, 32)
	rand.Read(salt)
	info := &Metadata{KeyID: k.active, Salt: salt}
	aead, err := k.cipher(info)
	if err != nil {
		return nil, nil, err
	}
	writer := &encryptWriter{out: file, aead: aead, info: info, buf: make([]byte, 0, encryptionBlock), aad: []byte(key)}
	return writer, writer.finish, nil
}

func (w *encryptWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), encryptionBlock-len(w.buf))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		total += n
		if len(w.buf) == encryptionBlock {
			if err := w.flush(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func blockNonce(index uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], index)
	return nonce
}

func (w *encryptWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	nonce := blockNonce(w.index)
	w.sealed = w.aead.Seal(w.sealed[:0], nonce[:], w.buf, w.aad)
	if _, err := w.out.Write(w.sealed); err != nil {
		return err
	}
	clear(w.buf)
	w.buf = w.buf[:0]
	w.index++
	return nil
}

func (w *encryptWriter) finish() (*Metadata, error) {
	if err := w.flush(); err != nil {
		return nil, err
	}
	return w.info, nil
}

type ReadCloserAt interface {
	io.ReaderAt
	io.Closer
}

func (k *Keys) Reader(data ReadCloserAt, key string, size int64, info *Metadata) (ReadCloserAt, error) {
	aead, err := k.cipher(info)
	if err != nil {
		return nil, err
	}
	return &decryptReader{ReadCloserAt: data, aead: aead, size: size, aad: []byte(key), cached: -1,
		ciphertext: make([]byte, encryptionBlock+encryptionTagSize), plaintext: make([]byte, 0, encryptionBlock)}, nil
}

func (k *Keys) SetActive(id string) { k.active = id }

func PayloadSize(size int64, info *Metadata) int64 {
	if info == nil {
		return size
	}
	return size + ((size+encryptionBlock-1)/encryptionBlock)*encryptionTagSize
}

type decryptReader struct {
	ReadCloserAt
	mu                    sync.Mutex
	aead                  cipher.AEAD
	size                  int64
	aad                   []byte
	cached                int64
	ciphertext, plaintext []byte
}

func (r *decryptReader) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative encrypted object offset")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for len(p) > 0 && offset < r.size {
		index := offset / encryptionBlock
		if r.cached != index {
			r.cached = -1
			count := min(int64(encryptionBlock), r.size-index*encryptionBlock)
			ciphertext := r.ciphertext[:count+encryptionTagSize]
			if _, err := r.ReadCloserAt.ReadAt(ciphertext, index*(encryptionBlock+encryptionTagSize)); err != nil {
				return total, err
			}
			nonce := blockNonce(uint64(index))
			plain, err := r.aead.Open(r.plaintext[:0], nonce[:], ciphertext, r.aad)
			if err != nil {
				return total, ErrCiphertext
			}
			r.plaintext = plain
			r.cached = index
		}
		start := offset % encryptionBlock
		n := copy(p, r.plaintext[start:])
		p = p[n:]
		offset += int64(n)
		total += n
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}
