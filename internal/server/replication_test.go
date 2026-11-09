package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type replicaTestTransport func(*http.Request) (*http.Response, error)

func (roundTrip replicaTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return roundTrip(r)
}

func TestReplicationStagesBeforePublishing(t *testing.T) {
	storage, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer storage.close()
	dir := filepath.Join(storage.dir, "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	good := object{Key: "good", Size: 4, VersionID: strings.Repeat("a", 32), Sequence: 1, SHA256: digest("good")}
	bad := object{Key: "bad", Size: 4, VersionID: strings.Repeat("b", 32), Sequence: 2, SHA256: digest("good")}
	body, err := json.Marshal(replicaManifest{Status: "Enabled", Versions: []object{bad, good}})
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	client := &http.Client{Transport: replicaTestTransport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/inventory") {
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		if strings.HasSuffix(r.URL.Path, "/manifest") {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
		}
		requests++
		payload := "good"
		if r.URL.Query().Get("key") == "bad" {
			payload = "oops"
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"X-Stash-Sha256": {good.SHA256}},
			Body:       io.NopCloser(strings.NewReader(payload)),
		}, nil
	})}
	service := &replication{store: storage, client: client}
	_, _, err = service.reconcile(context.Background(), "reports", replicaSource{Endpoint: "https://source.example", Bucket: "reports"})
	if err == nil || requests != 2 {
		t.Fatalf("expected checksum rejection after two transfers, got %d requests, %v", requests, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed cycle left files in the bucket: %v, %v", entries, err)
	}
}

func TestReplicaChangeFeedCatchUpAndReset(t *testing.T) {
	source, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	destination, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer destination.close()
	const bucket = "reports"
	const token = "replication-test-token-1234"
	dir := filepath.Join(source.dir, bucket)
	for _, path := range []string{dir, filepath.Join(destination.dir, bucket)} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeMetadataFile(dir, versionConfig, []byte("Enabled")); err != nil {
		t.Fatal(err)
	}
	export, err := configureReplication(config{ReplicationExports: map[string]string{bucket: token}}, source)
	if err != nil {
		t.Fatal(err)
	}
	handler := &server{store: source, replication: export}
	manifestCalls := 0
	client := &http.Client{Transport: replicaTestTransport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/inventory") {
			manifestCalls++
		}
		r.RemoteAddr = "127.0.0.1:12345"
		response := httptest.NewRecorder()
		handler.serveReplication(response, r)
		return response.Result(), nil
	})}
	replica := &replication{store: destination, client: client, status: map[string]replicaStatus{bucket: {}}}
	upstream := replicaSource{Endpoint: "http://127.0.0.1", Bucket: bucket, Token: token}
	put := func(body string) object {
		t.Helper()
		r := httptest.NewRequest("PUT", "/reports/report", strings.NewReader(body))
		r.Header.Set("X-Amz-Content-Sha256", digest(body))
		obj, err := source.put(bucket, "report", r)
		if err != nil {
			t.Fatal(err)
		}
		return obj
	}
	syncCheck := func(count, manifests int) replicaStatus {
		t.Helper()
		replica.sync(context.Background(), bucket, upstream)
		state, err := readReplicaStatus(filepath.Join(destination.dir, bucket))
		if err != nil || state.Cursor == "" || state.Versions != count ||
			manifestCalls != manifests || replica.status[bucket].LastError != "" {
			t.Fatalf("checkpoint %+v, manifest calls %d, sync error %q, read error %v", state, manifestCalls, replica.status[bucket].LastError, err)
		}
		return state
	}
	first := put("first")
	baseline := syncCheck(1, 2)
	second := put("second")
	if _, err := source.removeVersion(dir, first.Key, first.VersionID, false); err != nil {
		t.Fatal(err)
	}
	delta := syncCheck(1, 2)
	if baseline.Cursor == delta.Cursor {
		t.Fatal("delta checkpoint did not advance")
	}
	// A restarted replica uses the persisted cursor, including for idle polls.
	replica.status[bucket] = delta
	syncCheck(1, 2)
	replicaDir := filepath.Join(destination.dir, bucket)
	if _, err := os.Stat(replicaVersionPath(replicaDir, first.Key, first.VersionID)); !os.IsNotExist(err) {
		t.Fatalf("removed version still present: %v", err)
	}
	if obj, err := metadataAt(replicaVersionPath(replicaDir, second.Key, second.VersionID)); err != nil || obj.SHA256 != second.SHA256 {
		t.Fatalf("incremental version missing or invalid: %+v, %v", obj, err)
	}
	// A new source epoch forces a full reconciliation and records a new cursor.
	source.resetReplicaFeed(dir)
	put("third")
	reset := syncCheck(2, 4)
	if reset.Cursor == delta.Cursor {
		t.Fatal("source reset did not establish a new cursor")
	}
	syncCheck(2, 4)
}

func TestReplicaFeedRejectsExpiredCursor(t *testing.T) {
	storage := &store{replicaFeeds: map[string]*replicaFeed{"reports": newReplicaFeed()}}
	feed := storage.replicaFeeds["reports"]
	cursor := feed.changes("").Cursor
	for i := 0; i < replicaFeedCapacity; i++ {
		storage.recordReplicaChange("reports", object{Key: "same"}, i%2 != 0)
	}
	delta := feed.changes(cursor)
	if delta.Reset || len(delta.Changes) != 1 || delta.Changes[0].Object != nil {
		t.Fatalf("unexpected coalesced delta: %+v", delta)
	}
	storage.recordReplicaChange("reports", object{Key: "next"}, false)
	if !feed.changes(cursor).Reset {
		t.Fatal("expired cursor was accepted")
	}
}
