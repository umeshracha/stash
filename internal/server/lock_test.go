package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A client that stops sending must not hold up anyone else. The store lock is
// taken exclusively by listings, deletes and bucket changes, and a waiting
// exclusive lock holds back every new reader, so a lock held across a slow upload
// stalls the whole server.

func testStore(t *testing.T) *store {
	t.Helper()
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	if err := os.Mkdir(filepath.Join(store.dir, "reports"), 0700); err != nil {
		t.Fatal(err)
	}
	return store
}

// assertNotBlocked fails if an exclusive request cannot get in, or a reader is held back, now.
func assertNotBlocked(t *testing.T, store *store, during string) {
	t.Helper()
	exclusive := make(chan struct{})
	go func() {
		store.mu.Lock()
		store.mu.Unlock()
		close(exclusive)
	}()
	select {
	case <-exclusive:
	case <-time.After(2 * time.Second):
		t.Fatalf("a request needing the store lock exclusively waited behind %s", during)
	}
	if !store.mu.TryRLock() {
		t.Fatalf("a reader was held back by %s", during)
	}
	store.mu.RUnlock()
}

func TestStalledUploadDoesNotHoldTheStoreLock(t *testing.T) {
	store := testStore(t)
	pr, pw := io.Pipe()
	r := httptest.NewRequest("PUT", "/reports/slow", pr)
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	done := make(chan error, 1)
	go func() {
		_, err := store.put("reports", "slow", r)
		done <- err
	}()
	pw.Write([]byte("first bytes"))
	time.Sleep(100 * time.Millisecond) // the upload is now mid-body

	assertNotBlocked(t, store, "an upload in progress")

	pw.Write([]byte(" and the rest"))
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(store.dir, "reports", digest("slow")))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	obj, err := readMetadata(file)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(io.NewSectionReader(file, 0, obj.Size))
	if string(body) != "first bytes and the rest" {
		t.Fatalf("stored %q", body)
	}
}

// startPartUpload begins a multipart upload and returns its ID.
func startPartUpload(t *testing.T, s *server, key string) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/reports/"+key+"?uploads", nil)
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	s.multipart(w, r, "reports", key, url.Values{"uploads": {""}}, credential{})
	var result struct{ UploadId string }
	if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil || result.UploadId == "" {
		t.Fatalf("no upload ID in %d %s", w.Code, w.Body.String())
	}
	return result.UploadId
}

// sendPart runs an UploadPart whose body the test controls.
func sendPart(s *server, key, id string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/reports/"+key+"?partNumber=1&uploadId="+id, body)
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	s.multipart(w, r, "reports", key, url.Values{"partNumber": {"1"}, "uploadId": {id}}, credential{})
	return w
}

func TestStalledPartDoesNotHoldTheStoreLock(t *testing.T) {
	s := &server{store: testStore(t), region: "us-east-1"}
	id := startPartUpload(t, s, "big")

	pr, pw := io.Pipe()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- sendPart(s, "big", id, pr) }()
	pw.Write([]byte("part body"))
	time.Sleep(100 * time.Millisecond)

	assertNotBlocked(t, s.store, "a part upload in progress")
	// Nor does it hold the upload's own lock: other calls on this upload go through.
	list := httptest.NewRecorder()
	listed := make(chan struct{})
	go func() {
		s.multipart(list, httptest.NewRequest("GET", "/reports/big?uploadId="+id, nil), "reports", "big", url.Values{"uploadId": {id}}, credential{})
		close(listed)
	}()
	select {
	case <-listed:
	case <-time.After(2 * time.Second):
		t.Fatal("ListParts waited behind a part upload in progress")
	}

	pw.Close()
	if w := <-done; w.Code != 200 {
		t.Fatalf("UploadPart returned %d: %s", w.Code, w.Body.String())
	}

	// The part is stored and the upload completes into the object.
	etag := ""
	if parts, _ := os.ReadDir(filepath.Join(s.store.dir, "reports", ".mp-"+id)); len(parts) == 0 {
		t.Fatal("the part was not stored")
	}
	complete := httptest.NewRecorder()
	listParts := httptest.NewRecorder()
	s.multipart(listParts, httptest.NewRequest("GET", "/reports/big?uploadId="+id, nil), "reports", "big", url.Values{"uploadId": {id}}, credential{})
	var listing struct {
		Parts []struct{ ETag string } `xml:"Part"`
	}
	xml.Unmarshal(listParts.Body.Bytes(), &listing)
	if len(listing.Parts) == 1 {
		etag = listing.Parts[0].ETag
	}
	request := httptest.NewRequest("POST", "/reports/big?uploadId="+id,
		strings.NewReader(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>`+etag+`</ETag></Part></CompleteMultipartUpload>`))
	request.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	s.multipart(complete, request, "reports", "big", url.Values{"uploadId": {id}}, credential{})
	if complete.Code != 200 {
		t.Fatalf("CompleteMultipartUpload returned %d: %s", complete.Code, complete.Body.String())
	}
	file, err := os.Open(filepath.Join(s.store.dir, "reports", digest("big")))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	obj, err := readMetadata(file)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(io.NewSectionReader(file, 0, obj.Size))
	if string(body) != "part body" {
		t.Fatalf("assembled %q", body)
	}
}

func TestPartLandingAfterTheUploadWasAbortedIsRefused(t *testing.T) {
	s := &server{store: testStore(t), region: "us-east-1"}
	id := startPartUpload(t, s, "big")

	pr, pw := io.Pipe()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- sendPart(s, "big", id, pr) }()
	pw.Write([]byte("part body"))
	time.Sleep(100 * time.Millisecond)

	abort := httptest.NewRecorder()
	s.multipart(abort, httptest.NewRequest("DELETE", "/reports/big?uploadId="+id, nil), "reports", "big", url.Values{"uploadId": {id}}, credential{})
	if abort.Code != http.StatusNoContent {
		t.Fatalf("abort returned %d", abort.Code)
	}

	pw.Close()
	w := <-done
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "NoSuchUpload") {
		t.Fatalf("a part for an aborted upload got %d %s, want 404 NoSuchUpload", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(s.store.dir, "reports", ".mp-"+id)); !os.IsNotExist(err) {
		t.Fatalf("the aborted upload's directory came back: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.store.dir, "reports"))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".upload-") {
			t.Errorf("left %s behind", entry.Name())
		}
	}
}
