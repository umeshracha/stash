package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stash/internal/fsutil"
)

func TestLifecycleDoesNotPurgeProtectedHistory(t *testing.T) {
	storage, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer storage.close()
	dir := filepath.Join(storage.dir, "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileAtomic(dir, versionConfig, []byte("Enabled")); err != nil {
		t.Fatal(err)
	}
	put := func(key string) object {
		t.Helper()
		request := httptest.NewRequest("PUT", "/", strings.NewReader("data"))
		request.Header.Set("X-Amz-Content-Sha256", digest("data"))
		obj, err := storage.put("reports", key, request)
		if err != nil {
			t.Fatal(err)
		}
		return obj
	}
	held := put("expire/report")
	p := protectionPath(dir, digest(held.Key), held.VersionID)
	if err := os.WriteFile(p, []byte(`{"LegalHold":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	unheld := put("expire/report")
	current := put("expire/report")
	untouched := put("keep/report")
	config := []byte(`<LifecycleConfiguration><Rule><ID>expiration</ID><Status>Enabled</Status>
		<Filter><Prefix>expire/</Prefix></Filter><Expiration><Days>1</Days></Expiration>
		<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>
		<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload>
		</Rule></LifecycleConfiguration>`)
	if err := fsutil.WriteFileAtomic(dir, lifecycleFile, config); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(dir, ".mp-"+strings.Repeat("a", 32))
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := json.Marshal(uploadInfo{Key: "expire/incomplete", Created: time.Now().Add(-72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "upload.json"), info, 0600); err != nil {
		t.Fatal(err)
	}
	if count, err := storage.applyLifecycle(time.Now().Add(72 * time.Hour)); err != nil || count != 3 {
		t.Fatalf("expected a marker, one expired version, and an aborted upload: %d, %v", count, err)
	}
	list, err := versionsFor(dir, digest(held.Key))
	if err != nil || len(list) != 3 || !list[0].DeleteMarker ||
		list[1].VersionID != current.VersionID || list[2].VersionID != held.VersionID {
		t.Fatalf("unexpected versions after expiration, deleted candidate %s: %v, %v", unheld.VersionID, list, err)
	}
	other, err := versionsFor(dir, digest(untouched.Key))
	if err != nil || len(other) != 1 || other[0].VersionID != untouched.VersionID {
		t.Fatalf("prefix filter failed: %v, %v", other, err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("expired multipart upload remained: %v", err)
	}
}

func TestLifecycleRejectsUnsupportedFilters(t *testing.T) {
	config := []byte(`<LifecycleConfiguration><Rule><Status>Enabled</Status>
		<Filter><Tag><Key>team</Key><Value>test</Value></Tag></Filter>
		<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`)
	if _, err := parseLifecycle(config); err == nil {
		t.Fatal("accepting unsupported filters could expire unrelated objects")
	}
}
