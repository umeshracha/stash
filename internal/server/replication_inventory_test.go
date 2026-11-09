package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplicaInventoryBeyondLegacyLimit(t *testing.T) {
	storage, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer storage.close()
	dir := filepath.Join(storage.dir, "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeMetadataFile(dir, versionConfig, []byte("Enabled")); err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("a", 60<<10)
	const count = 550
	for i := range count {
		key := fmt.Sprintf("report-%d", i)
		metadata, err := json.Marshal(object{Key: key, Headers: http.Header{"X-Amz-Meta-Data": {value}}})
		if err != nil {
			t.Fatal(err)
		}
		data := binary.BigEndian.AppendUint32(metadata, uint32(len(metadata)))
		if err := os.WriteFile(filepath.Join(dir, digest(key)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	server := &server{store: storage}
	response := httptest.NewRecorder()
	server.serveReplicaInventory(response, httptest.NewRequest("GET", "/inventory", nil), dir)
	if response.Code != 200 || response.Body.Len() <= maxManifest {
		t.Fatalf("inventory response status %d, bytes %d", response.Code, response.Body.Len())
	}
	// Verify the second read can compare the snapshot without retaining its objects.
	manifest, revision, err := readReplicaInventory(bytes.NewReader(response.Body.Bytes()), false)
	if err != nil || manifest.Status != "Enabled" || len(manifest.Versions) != 0 || len(revision) != 64 {
		t.Fatalf("digest-only read failed: status %s, objects %d, revision %s, error %v", manifest.Status, len(manifest.Versions), revision, err)
	}
	manifest, collected, err := readReplicaInventory(response.Body, true)
	if err != nil || len(manifest.Versions) != count || collected != revision {
		t.Fatalf("collected %d versions, revision %s, error %v", len(manifest.Versions), collected, err)
	}
}

func TestReplicaInventoryRejectsIncompleteStreams(t *testing.T) {
	const header = "{\"Status\":\"Enabled\"}\n"
	for name, body := range map[string]string{
		"missing terminal": header + "{}\n",
		"extra data":       header + "null\n{}\n",
		"invalid version":  header + "broken\nnull\n",
		"oversized record": header + strings.Repeat(" ", maxInventoryRecord) + "\nnull\n",
	} {
		t.Run(name, func(t *testing.T) {
			reader := strings.NewReader(body)
			if _, _, err := readReplicaInventory(reader, true); err == nil {
				t.Fatal("accepted invalid inventory")
			}
		})
	}
}
