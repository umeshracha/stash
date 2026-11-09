package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"stash/internal/erasure"
	"stash/internal/etcd"
)

func TestClusterRejectsAndDiscardsConflictingMutation(t *testing.T) {
	dir := t.TempDir()
	layout := []byte("fixed layout")
	if err := os.WriteFile(filepath.Join(dir, erasure.LayoutFile), layout, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotMetadata(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: replicaTestTransport(func(r *http.Request) (*http.Response, error) {
		result := any(map[string]bool{"succeeded": false})
		if r.URL.Path == "/v3/kv/range" {
			result = map[string]any{
				"header": map[string]string{"cluster_id": "fixture"},
				"kvs":    []any{map[string]any{"value": snapshot, "mod_revision": "7"}},
			}
		}
		encoded, err := json.Marshal(result)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(encoded))}, err
	})}
	cluster := &metadataCluster{store: &store{dir: dir}, etcd: etcd.NewWithHTTP([]string{"https://etcd.example"}, "", "", client), revision: "7"}
	bucket := filepath.Join(dir, "reports")
	handler := cluster.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if err := os.Mkdir(bucket, 0700); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(200)
			return
		}
		if _, err := os.Stat(bucket); !os.IsNotExist(err) {
			t.Fatalf("conflicting mutation remained visible: %v", err)
		}
		w.WriteHeader(404)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/reports", nil))
	if response.Code != 503 {
		t.Fatalf("uncommitted mutation was acknowledged with status %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/reports", nil))
	if response.Code != 404 {
		t.Fatalf("read did not restore authoritative metadata, status %d", response.Code)
	}
}
