package erasure

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"

	"stash/internal/fsutil"
)

const shardBlockSize = 256 << 10
const shardRecordSize = shardBlockSize + sha256.Size
const LayoutFile = ".erasure-layout"

var ErrQuorum = errors.New("erasure shard quorum unavailable")

type Config struct {
	Nodes  []Node   `json:"nodes"`
	Drives []string `json:"drives"`
	Parity int      `json:"parity"`
}

type Store struct {
	nodes       []Node
	client      *http.Client
	scratch     string
	id          string
	roots       []string
	namespace   string
	drives      []string
	data        int
	writeQuorum int
	code        reedsolomon.Encoder
}

func Open(dir string, cfg *Config) (*Store, error) {
	saved, err := os.ReadFile(filepath.Join(dir, LayoutFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if cfg == nil {
		if len(saved) != 0 {
			return nil, errors.New("erasure configuration required for this data directory")
		}
		return nil, nil
	}
	n := len(cfg.Drives) + len(cfg.Nodes)
	if len(cfg.Drives) != 0 && len(cfg.Nodes) != 0 {
		return nil, errors.New("configure erasure drives or shard nodes")
	}
	if n < 3 || n > 16 || cfg.Parity < 1 || cfg.Parity > n/2 {
		return nil, errors.New("erasure configuration requires 3–16 drives and parity between 1 and half the drive count")
	}
	drives := make([]string, n)
	seen := make(map[string]bool, n)
	nodes := make([]Node, len(cfg.Nodes))
	for i, node := range cfg.Nodes {
		node, err := ValidateNode(node)
		if err != nil || seen[node.Endpoint] {
			return nil, fmt.Errorf("invalid or duplicate shard node %d", i+1)
		}
		nodes[i] = node
		seen[node.Endpoint] = true
		drives[i] = node.Endpoint
	}
	for i, path := range cfg.Drives {
		abs, err := filepath.Abs(path)
		if err != nil || path == "" || seen[abs] {
			return nil, errors.New("erasure drive paths must be unique")
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err == nil && resolved != abs {
			return nil, fmt.Errorf("erasure drive %d must use its physical path", i+1)
		}
		seen[abs] = true
		drives[i] = abs
	}
	layout := struct {
		Drives []string
		Parity int
		ID     string
	}{Drives: drives, Parity: cfg.Parity}
	if len(saved) != 0 {
		if err := json.Unmarshal(saved, &layout); err != nil || !ValidID(layout.ID) ||
			len(layout.Drives) != n || layout.Parity != cfg.Parity {
			return nil, errors.New("invalid or incompatible erasure layout")
		}
		for i, drive := range drives {
			if layout.Drives[i] != drive {
				return nil, errors.New("erasure drive order and parity are fixed for this data directory")
			}
		}
	} else {
		for i, drive := range cfg.Drives {
			info, err := os.Stat(drive)
			if err != nil || !info.IsDir() {
				return nil, fmt.Errorf("initialize erasure drive %d as an existing directory", i+1)
			}
		}
		var entropy [16]byte
		rand.Read(entropy[:])
		layout.ID = hex.EncodeToString(entropy[:])
	}
	data := n - cfg.Parity
	code, err := reedsolomon.New(data, cfg.Parity)
	if err != nil {
		return nil, err
	}
	ec := &Store{roots: drives, namespace: ".stash-erasure-" + layout.ID, drives: make([]string, n),
		nodes: nodes, id: layout.ID, scratch: dir,
		data: data, writeQuorum: max(data, n/2+1), code: code}
	if len(nodes) != 0 {
		ec.client = &http.Client{
			Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
				TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 60 * time.Second,
				MaxIdleConnsPerHost: 4, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".stash-shard-") || strings.HasPrefix(entry.Name(), ".stash-heal-") {
				if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
					return nil, err
				}
			}
		}
	}
	for i := range cfg.Drives {
		drive := drives[i]
		ec.drives[i] = filepath.Join(drive, ec.namespace)
		if len(saved) == 0 {
			if err := ec.InitializeDrive(i); err != nil {
				return nil, err
			}
		}
	}
	if len(saved) == 0 {
		encoded, err := json.Marshal(layout)
		if err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(dir, LayoutFile, encoded); err != nil {
			return nil, err
		}
	}
	return ec, nil
}

func (ec *Store) InitializeDrive(index int) error {
	if index < 0 || index >= len(ec.drives) {
		return errors.New("erasure drive index out of range")
	}
	if len(ec.nodes) != 0 {
		return nil
	}
	if err := os.Mkdir(ec.drives[index], 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return fsutil.SyncDir(ec.roots[index])
}

func (ec *Store) shardPath(index int, id string) string {
	return filepath.Join(ec.drives[index], id+".shard")
}

func (ec *Store) Encode(reader io.ReaderAt, size int64) (string, error) {
	var entropy [16]byte
	rand.Read(entropy[:])
	id := hex.EncodeToString(entropy[:])
	files := make([]*os.File, len(ec.drives))
	defer func() {
		for _, file := range files {
			if file != nil {
				file.Close()
				os.Remove(file.Name())
			}
		}
	}()
	available := 0
	for i := range ec.drives {
		file, err := ec.stage(i, ".stash-shard-")
		if err == nil {
			files[i] = file
			available++
		}
	}
	if available < ec.writeQuorum {
		return "", ErrQuorum
	}
	stripeSize := int64(ec.data * shardBlockSize)
	shards := make([][]byte, len(files))
	for i := range shards {
		shards[i] = make([]byte, shardBlockSize)
	}
	for stripe := int64(0); stripe*stripeSize < size; stripe++ {
		for i := range ec.data {
			clear(shards[i])
			offset := stripe*stripeSize + int64(i*shardBlockSize)
			count := min(int64(shardBlockSize), max(0, size-offset))
			if count == 0 {
				continue
			}
			if n, err := reader.ReadAt(shards[i][:count], offset); err != nil || int64(n) != count {
				return "", io.ErrUnexpectedEOF
			}
		}
		if err := ec.code.Encode(shards); err != nil {
			return "", err
		}
		for i, file := range files {
			if file == nil {
				continue
			}
			if err := writeShardBlock(file, shards[i]); err != nil {
				file.Close()
				os.Remove(file.Name())
				files[i] = nil
				available--
			}
		}
		if available < ec.writeQuorum {
			return "", ErrQuorum
		}
	}
	written := ec.publishShards(files, id)
	if written < ec.writeQuorum {
		if len(ec.nodes) == 0 {
			for i := range files {
				os.Remove(ec.shardPath(i, id))
			}
		}
		return "", ErrQuorum
	}
	return id, nil
}

func writeShardBlock(file *os.File, block []byte) error {
	hash := sha256.Sum256(block)
	if _, err := file.Write(hash[:]); err != nil {
		return err
	}
	_, err := file.Write(block)
	return err
}

func publishShard(file *os.File, path string) error {
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return fsutil.SyncDir(filepath.Dir(path))
}

type erasureReader struct {
	mu          sync.Mutex
	block       []byte
	cachedBlock int64
	ec          *Store
	size        int64
	files       []shardReader
}

func (ec *Store) OpenObject(id string, size int64) (*erasureReader, error) {
	if !ValidID(id) {
		return nil, errors.New("invalid erasure object id")
	}
	r := &erasureReader{ec: ec, size: size, files: make([]shardReader, len(ec.drives)), cachedBlock: -1}
	var wg sync.WaitGroup
	for i := range r.files {
		wg.Go(func() { r.files[i] = ec.openShard(i, id) })
	}
	wg.Wait()
	count := 0
	for _, file := range r.files {
		if file != nil {
			count++
		}
	}
	if count < ec.data {
		r.Close()
		return nil, ErrQuorum
	}
	return r, nil
}

func (r *erasureReader) Close() error {
	for _, file := range r.files {
		if file != nil {
			file.Close()
		}
	}
	return nil
}

func readShardBlock(file shardReader, stripe int64, block []byte) bool {
	if file == nil {
		return false
	}
	record := make([]byte, shardRecordSize)
	if _, err := file.ReadAt(record, stripe*shardRecordSize); err != nil {
		return false
	}
	expected := [sha256.Size]byte(record[:sha256.Size])
	if sha256.Sum256(record[sha256.Size:]) != expected {
		return false
	}
	copy(block, record[sha256.Size:])
	return true
}

func (r *erasureReader) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative offset")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	if r.block == nil {
		r.block = make([]byte, shardBlockSize)
	}
	for len(p) > 0 && offset < r.size {
		blockNumber := offset / shardBlockSize
		stripe := blockNumber / int64(r.ec.data)
		index := int(blockNumber % int64(r.ec.data))
		if r.cachedBlock != blockNumber {
			r.cachedBlock = -1
			if !readShardBlock(r.files[index], stripe, r.block) {
				shards := r.readStripe(stripe)
				if err := r.ec.code.ReconstructData(shards); err != nil {
					return total, ErrQuorum
				}
				copy(r.block, shards[index])
			}
			r.cachedBlock = blockNumber
		}
		start := offset % shardBlockSize
		count := min(int64(len(p)), shardBlockSize-start, r.size-offset)
		copy(p, r.block[start:start+count])
		p = p[count:]
		total += int(count)
		offset += count
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}

func (r *erasureReader) readStripe(stripe int64) [][]byte {
	shards := make([][]byte, len(r.files))
	var wg sync.WaitGroup
	for i, file := range r.files {
		if file == nil {
			continue
		}
		wg.Go(func() {
			block := make([]byte, shardBlockSize)
			if readShardBlock(file, stripe, block) {
				shards[i] = block
			}
		})
	}
	wg.Wait()

	return shards
}

// heal verifies every stripe and replaces damaged shards only after a complete reconstruction.
func (ec *Store) Heal(id string, size int64) (int, error) {
	reader, err := ec.OpenObject(id, size)
	if err != nil {
		return 0, err
	}
	defer reader.Close()
	stripeSize := int64(ec.data * shardBlockSize)
	stripes := (size + stripeSize - 1) / stripeSize
	damaged := make([]bool, len(reader.files))
	block := make([]byte, shardBlockSize)
	count := 0
	for i, file := range reader.files {
		if file == nil {
			damaged[i] = true
		} else if file.shardSize() != stripes*shardRecordSize {
			damaged[i] = true
		}
		for stripe := int64(0); stripe < stripes && !damaged[i]; stripe++ {
			damaged[i] = !readShardBlock(file, stripe, block)
		}
		if damaged[i] {
			count++
		}
	}
	if count == 0 {
		return 0, nil
	}
	staging := make([]*os.File, len(ec.drives))
	defer func() {
		for _, file := range staging {
			if file != nil {
				file.Close()
				os.Remove(file.Name())
			}
		}
	}()
	for i, bad := range damaged {
		if !bad {
			continue
		}
		file, err := ec.stage(i, ".stash-heal-")
		if err == nil {
			staging[i] = file
		}
	}
	for stripe := int64(0); stripe < stripes; stripe++ {
		shards := reader.readStripe(stripe)
		if err := ec.code.Reconstruct(shards); err != nil {
			return 0, ErrQuorum
		}
		for i, file := range staging {
			if file != nil {
				if err := writeShardBlock(file, shards[i]); err != nil {
					return 0, err
				}
			}
		}
	}
	repaired := ec.publishShards(staging, id)
	if repaired < count {
		return repaired, ErrQuorum
	}
	return repaired, nil
}

func (ec *Store) RemoveUnreferenced(referenced map[string]bool) error {
	if len(ec.nodes) != 0 {
		return ec.removeUnreferencedRemote(referenced)
	}
	for _, drive := range ec.drives {
		entries, err := os.ReadDir(drive)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		changed := false
		for _, entry := range entries {
			name := entry.Name()
			id, isShard := strings.CutSuffix(name, ".shard")
			if !isShard || !ValidID(id) || referenced[id] || !entry.Type().IsRegular() {
				continue
			}
			if err := os.Remove(filepath.Join(drive, name)); err != nil {
				return err
			}
			changed = true
		}
		if changed {
			if err := fsutil.SyncDir(drive); err != nil {
				return err
			}
		}
	}
	return nil
}

type shardReader interface {
	io.ReaderAt
	io.Closer
	shardSize() int64
}

type localShard struct {
	*os.File
	size int64
}

func (s localShard) shardSize() int64   { return s.size }
func (s *remoteShard) shardSize() int64 { return s.size }

func (ec *Store) stage(index int, prefix string) (*os.File, error) {
	if len(ec.nodes) != 0 {
		return os.CreateTemp(ec.scratch, prefix)
	}
	return os.CreateTemp(ec.drives[index], prefix)
}

func (ec *Store) peer(index int, id string) *remoteShard {
	node := ec.nodes[index]
	return &remoteShard{client: ec.client, endpoint: node.Endpoint + shardRoute + ec.id + "/" + id, token: node.Token}
}

func (ec *Store) openShard(index int, id string) shardReader {
	if len(ec.nodes) != 0 {
		shard := ec.peer(index, id)
		response, err := shard.request(http.MethodHead, nil, 0, "")
		if err != nil {
			return nil
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || response.ContentLength < 0 {
			return nil
		}
		shard.size = response.ContentLength
		return shard
	}
	file, err := os.Open(ec.shardPath(index, id))
	if err != nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil
	}
	return localShard{File: file, size: info.Size()}
}

func (ec *Store) publishShards(files []*os.File, id string) int {
	var wg sync.WaitGroup
	results := make([]bool, len(files))
	for i, file := range files {
		if file == nil {
			continue
		}
		wg.Go(func() {
			if len(ec.nodes) == 0 {
				results[i] = publishShard(file, ec.shardPath(i, id)) == nil
				return
			}
			info, err := file.Stat()
			if err != nil {
				return
			}
			response, err := ec.peer(i, id).request(http.MethodPut, io.NewSectionReader(file, 0, info.Size()), info.Size(), "")
			if err != nil {
				return
			}
			defer response.Body.Close()
			results[i] = response.StatusCode == http.StatusCreated
		})
	}
	wg.Wait()
	written := 0
	for _, ok := range results {
		if ok {
			written++
		}
	}
	return written
}

func (ec *Store) removeUnreferencedRemote(referenced map[string]bool) error {
	for i, node := range ec.nodes {
		inventory := &remoteShard{client: ec.client, endpoint: node.Endpoint + shardRoute + ec.id, token: node.Token}
		response, err := inventory.request(http.MethodGet, nil, 0, "")
		if err != nil {
			return fmt.Errorf("shard node %d inventory: %w", i+1, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxShardInventory+1))
		response.Body.Close()
		var ids []string
		if readErr != nil || response.StatusCode != http.StatusOK || len(data) > maxShardInventory || json.Unmarshal(data, &ids) != nil {
			return fmt.Errorf("invalid inventory from shard node %d", i+1)
		}
		for _, id := range ids {
			if !ValidID(id) {
				return fmt.Errorf("invalid shard id from node %d", i+1)
			}
			if referenced[id] {
				continue
			}
			result, err := ec.peer(i, id).request(http.MethodDelete, nil, 0, "")
			if err != nil {
				return fmt.Errorf("delete shard from node %d: %w", i+1, err)
			}
			result.Body.Close()
			if result.StatusCode != http.StatusNoContent {
				return fmt.Errorf("shard node %d rejected cleanup", i+1)
			}
		}
	}
	return nil
}

// Readiness requires enough reachable shard locations for a write.
func (ec *Store) Ready() bool {
	results := make([]bool, len(ec.drives))
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			if len(ec.nodes) == 0 {
				info, err := os.Stat(ec.drives[i])
				results[i] = err == nil && info.IsDir()
				return
			}
			node := ec.nodes[i]
			peer := &remoteShard{client: ec.client, endpoint: node.Endpoint + shardRoute + ec.id, token: node.Token}
			response, err := peer.request(http.MethodHead, nil, 0, "")
			if err != nil {
				return
			}
			defer response.Body.Close()
			results[i] = response.StatusCode == 200
		})
	}
	wg.Wait()
	count := 0
	for _, ready := range results {
		if ready {
			count++
		}
	}
	return count >= ec.writeQuorum
}
