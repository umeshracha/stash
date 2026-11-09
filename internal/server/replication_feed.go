package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const replicaFeedCapacity = 256

// A restarted source issues a new epoch and requires a fresh baseline.
type replicaFeed struct {
	mu     sync.Mutex
	epoch  string
	head   uint64
	events [replicaFeedCapacity]replicaChange
}

type replicaChange struct {
	Key    replicaKey
	Object *object `json:",omitempty"`
}

type replicaDelta struct {
	Cursor  string
	Reset   bool `json:",omitempty"`
	Status  string
	Lock    *lockConfiguration `json:",omitempty"`
	Changes []replicaChange    `json:",omitempty"`
}

func newReplicaFeed() *replicaFeed {
	feed := &replicaFeed{}
	feed.reset()
	return feed
}

func (feed *replicaFeed) reset() {
	feed.mu.Lock()
	defer feed.mu.Unlock()
	var nonce [16]byte
	rand.Read(nonce[:])
	feed.epoch = hex.EncodeToString(nonce[:])
	feed.head = 0
	clear(feed.events[:])
}

// Mutation callers hold the store or version lock through publication and recording.
func (s *store) recordReplicaChange(dir string, obj object, deleted bool) {
	feed := s.replicaFeeds[filepath.Base(dir)]
	if feed == nil {
		return
	}
	change := replicaChange{Key: replicaKey{obj.Key, obj.VersionID}}
	if change.Key.Version == "" {
		change.Key.Version = "null"
	}
	if !deleted {
		obj.VersionID = change.Key.Version
		obj.Encryption = nil
		obj.ErasureID = ""
		change.Object = &obj
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	feed.events[feed.head%replicaFeedCapacity] = change
	feed.head++
}

func (s *store) resetReplicaFeed(dir string) {
	if feed := s.replicaFeeds[filepath.Base(dir)]; feed != nil {
		feed.reset()
	}
}

func (feed *replicaFeed) changes(cursor string) replicaDelta {
	feed.mu.Lock()
	defer feed.mu.Unlock()
	delta := replicaDelta{Cursor: feed.epoch + ":" + strconv.FormatUint(feed.head, 10)}
	epoch, position, _ := strings.Cut(cursor, ":")
	start, err := strconv.ParseUint(position, 10, 64)
	if err != nil || epoch != feed.epoch || start > feed.head || feed.head-start > replicaFeedCapacity {
		delta.Reset = true
		return delta
	}
	// Only the final state of each version is needed at the checkpoint.
	seen := make(map[replicaKey]bool)
	for i := feed.head; i > start; i-- {
		change := feed.events[(i-1)%replicaFeedCapacity]
		if !seen[change.Key] {
			seen[change.Key] = true
			delta.Changes = append(delta.Changes, change)
		}
	}
	return delta
}

func (s *server) serveReplicaChanges(w http.ResponseWriter, r *http.Request, bucket, dir string) {
	feed := s.store.replicaFeeds[bucket]
	if feed == nil {
		http.NotFound(w, r)
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if err := checkReplicaCheckpoint(dir); err != nil {
		http.Error(w, "replica checkpoint unavailable", 503)
		return
	}
	status, err := versionStatus(dir)
	if err != nil || status == "" {
		http.Error(w, "versioned bucket unavailable", 409)
		return
	}
	lock, err := readLockConfig(dir)
	if err != nil {
		http.Error(w, "object lock configuration unavailable", 503)
		return
	}
	delta := feed.changes(r.URL.Query().Get("cursor"))
	delta.Status, delta.Lock = status, lock
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(delta)
}
