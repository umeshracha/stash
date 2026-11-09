package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"stash/internal/audit"
	"stash/internal/fsutil"
)

const analyticsFile = ".analytics.json"
const analyticsRetention = 30 * 24 * time.Hour
const analyticsSeriesLimit = 50000

var latencyBounds = [...]int64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000}

type analyticsKey struct {
	Hour                   int64
	Bucket, App, Operation string
}

type analyticsRow struct {
	analyticsKey
	Requests, Errors, Uploaded, Downloaded uint64
	Latency                                [len(latencyBounds) + 1]uint64
}

func (r analyticsRow) p95() string {
	target := (r.Requests*95 + 99) / 100
	var seen uint64
	for i, count := range r.Latency {
		seen += count
		if seen >= target {
			if i == len(latencyBounds) {
				return ">60000"
			}
			return formatInt(latencyBounds[i])
		}
	}
	return ""
}

type storageSampleKey struct {
	Hour   int64
	Bucket string
}
type storageSample struct {
	storageSampleKey
	Bytes uint64
}
type analyticsCheckpoint struct {
	Traffic []analyticsRow
	Storage []storageSample
}

type analytics struct {
	storage map[storageSampleKey]storageSample
	mu      sync.Mutex
	dir     string
	rows    map[analyticsKey]analyticsRow
	dirty   bool
}

func openAnalytics(dir string) (*analytics, error) {
	a := &analytics{dir: dir, rows: map[analyticsKey]analyticsRow{}, storage: map[storageSampleKey]storageSample{}}
	file, err := os.Open(filepath.Join(dir, analyticsFile))
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var checkpoint analyticsCheckpoint
	if err := json.NewDecoder(io.LimitReader(file, 32<<20)).Decode(&checkpoint); err != nil {
		return nil, err
	}
	if len(checkpoint.Traffic) > analyticsSeriesLimit+24*31 || len(checkpoint.Storage) > analyticsSeriesLimit {
		return nil, errors.New("invalid analytics series count")
	}
	for _, row := range checkpoint.Traffic {
		a.rows[row.analyticsKey] = row
	}
	for _, sample := range checkpoint.Storage {
		a.storage[sample.storageSampleKey] = sample
	}
	a.prune(time.Now())
	return a, nil
}

func (a *analytics) prune(now time.Time) {
	oldest := now.UTC().Truncate(time.Hour).Add(-analyticsRetention).Unix()
	for key := range a.storage {
		if key.Hour < oldest {
			delete(a.storage, key)
			a.dirty = true
		}
	}
	for key := range a.rows {
		if key.Hour < oldest {
			delete(a.rows, key)
			a.dirty = true
		}
	}
}

func (a *analytics) flush() error {
	a.mu.Lock()
	a.prune(time.Now())
	if !a.dirty {
		a.mu.Unlock()
		return nil
	}
	rows := make([]analyticsRow, 0, len(a.rows))
	for _, row := range a.rows {
		rows = append(rows, row)
	}
	samples := make([]storageSample, 0, len(a.storage))
	for _, sample := range a.storage {
		samples = append(samples, sample)
	}
	a.dirty = false
	a.mu.Unlock()
	data, err := json.Marshal(analyticsCheckpoint{Traffic: rows, Storage: samples})
	if err == nil {
		err = fsutil.WriteFileAtomic(a.dir, analyticsFile, data)
	}
	if err != nil {
		a.mu.Lock()
		a.dirty = true
		a.mu.Unlock()
	}
	return err
}

func (a *analytics) run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.flush(); err != nil {
				log.Printf("analytics checkpoint: %v", err)
			}
		}
	}
}

func (a *analytics) record(key analyticsKey, status int, elapsed time.Duration, received, sent uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, exists := a.rows[key]
	if !exists && len(a.rows) >= analyticsSeriesLimit {
		key.Bucket, key.App, key.Operation = "", "", "Other"
		row = a.rows[key]
	}
	row.analyticsKey = key
	row.Requests++
	if status >= 400 {
		row.Errors++
	}
	if key.Operation == "PutObject" || key.Operation == "UploadPart" {
		row.Uploaded += received
	}
	if key.Operation == "GetObject" && status < 400 {
		row.Downloaded += sent
	}
	i := sort.Search(len(latencyBounds), func(i int) bool { return elapsed.Microseconds() <= latencyBounds[i]*1000 })
	row.Latency[i]++
	a.rows[key] = row
	a.dirty = true
}

type analyticsRequestContext struct{}
type requestTraffic struct {
	bucket, app, credential string
	received                uint64
}

type trackedBody struct {
	io.ReadCloser
	traffic *requestTraffic
}

func (b trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.traffic.received += uint64(n)
	return n, err
}

type trackedResponse struct {
	http.ResponseWriter
	status int
	sent   uint64
}

func (w *trackedResponse) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackedResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.sent += uint64(n)
	return n, err
}

func (w *trackedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func trackRequests(next http.Handler, a *analytics, auditLog *audit.Log) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || strings.HasPrefix(r.URL.Path, "/.stash/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		traffic := &requestTraffic{}
		var requestID string
		if auditLog != nil {
			var id [16]byte
			rand.Read(id[:])
			requestID = hex.EncodeToString(id[:])
			w.Header().Set("X-Amz-Request-Id", requestID)
		}
		r = r.WithContext(context.WithValue(r.Context(), analyticsRequestContext{}, traffic))
		if r.Body != nil {
			r.Body = trackedBody{r.Body, traffic}
		}
		out := &trackedResponse{ResponseWriter: w}
		next.ServeHTTP(out, r)
		status := out.status
		if status == 0 {
			status = 200
		}
		elapsed := time.Since(start)
		operation := s3Operation(r)
		if a != nil {
			a.record(analyticsKey{Hour: start.UTC().Truncate(time.Hour).Unix(), Bucket: traffic.bucket, App: traffic.app,
				Operation: operation}, status, elapsed, traffic.received, out.sent)
		}
		if auditLog != nil {
			auditLog.Record(audit.Event{Time: start.UTC(), RequestID: requestID, Credential: traffic.credential,
				Bucket: traffic.bucket, Operation: operation, Status: status, DurationMS: elapsed.Milliseconds()})
		}

	})
}

func s3Operation(r *http.Request) string {
	_, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	q := r.URL.Query()
	switch {
	case q.Has("uploads") && r.Method == http.MethodPost:
		return "CreateMultipartUpload"
	case q.Has("uploadId"):
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("X-Amz-Copy-Source") != "" {
				return "UploadPartCopy"
			}
			return "UploadPart"
		case http.MethodPost:
			return "CompleteMultipartUpload"
		case http.MethodDelete:
			return "AbortMultipartUpload"
		case http.MethodGet:
			return "ListParts"
		}
	case q.Has("retention") || q.Has("legal-hold"):
		suffix := "ObjectRetention"
		if q.Has("legal-hold") {
			suffix = "ObjectLegalHold"
		}
		if r.Method == http.MethodGet {
			return "Get" + suffix
		}
		if r.Method == http.MethodPut {
			return "Put" + suffix
		}
	case key != "":
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("X-Amz-Copy-Source") != "" {
				return "CopyObject"
			}
			return "PutObject"
		case http.MethodGet:
			return "GetObject"
		case http.MethodHead:
			return "HeadObject"
		case http.MethodDelete:
			return "DeleteObject"
		}
	case q.Has("delete") && r.Method == http.MethodPost:
		return "DeleteObjects"
	case q.Has("versions") && r.Method == http.MethodGet:
		return "ListObjectVersions"
	case q.Has("list-type") && r.Method == http.MethodGet:
		return "ListObjects"
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		return "ListBuckets"
	case q.Has("object-lock"):
		if r.Method == http.MethodGet {
			return "GetObjectLockConfiguration"
		}
		if r.Method == http.MethodPut {
			return "PutObjectLockConfiguration"
		}

	case q.Has("lifecycle"):
		switch r.Method {
		case http.MethodGet:
			return "GetBucketLifecycleConfiguration"
		case http.MethodPut:
			return "PutBucketLifecycleConfiguration"
		case http.MethodDelete:
			return "DeleteBucketLifecycle"
		}
	case q.Has("policy"):
		switch r.Method {
		case http.MethodGet:
			return "GetBucketPolicy"
		case http.MethodPut:
			return "PutBucketPolicy"
		case http.MethodDelete:
			return "DeleteBucketPolicy"
		}
	case q.Has("versioning"):
		if r.Method == http.MethodGet {
			return "GetBucketVersioning"
		}
		if r.Method == http.MethodPut {
			return "PutBucketVersioning"
		}
	case q.Has("location") && r.Method == http.MethodGet:
		return "GetBucketLocation"
	case r.Method == http.MethodPut:
		return "CreateBucket"
	case r.Method == http.MethodDelete:
		return "DeleteBucket"
	case r.Method == http.MethodHead:
		return "HeadBucket"
	}
	return "Other"
}

func (a *analytics) selectRows(bucket, app, operation string, hours int) []analyticsRow {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Hour)
	earliest := now.Add(-time.Duration(hours-1) * time.Hour).Unix()
	rows := make([]analyticsRow, 0)
	for key, row := range a.rows {
		if key.Hour >= earliest && key.Hour <= now.Unix() && (bucket == "" || key.Bucket == bucket) &&
			(app == "" || key.App == app) && (operation == "" || key.Operation == operation) {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Hour != b.Hour {
			return a.Hour > b.Hour
		}
		if a.Bucket != b.Bucket {
			return a.Bucket < b.Bucket
		}
		if a.App != b.App {
			return a.App < b.App
		}
		return a.Operation < b.Operation
	})
	return rows
}

func (a *analytics) sampleUsage(ctx context.Context, s *store, cluster *metadataCluster) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var lastHour int64 = -1
	for {
		now := time.Now().UTC().Truncate(time.Hour).Unix()
		if now != lastHour {
			var page dashboard
			var err error
			if cluster != nil {
				cluster.mu.Lock()
				_, _, err = cluster.refresh(ctx)
			}
			if err == nil {
				err = scanDashboard(s, &page, "")
			}
			if cluster != nil {
				cluster.mu.Unlock()
			}
			if err == nil {
				a.mu.Lock()
				a.prune(time.Now())
				values := map[string]uint64{"": page.StoredBytes}
				for _, bucket := range page.Buckets {
					values[bucket.Name] = bucket.StoredBytes
				}
				for bucket, size := range values {
					key := storageSampleKey{Hour: now, Bucket: bucket}
					if _, exists := a.storage[key]; exists || len(a.storage) < analyticsSeriesLimit {
						a.storage[key] = storageSample{storageSampleKey: key, Bytes: size}
						a.dirty = true
					}
				}
				a.mu.Unlock()
				lastHour = now
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *analytics) storageSeries(bucket string, hours int) []storageSample {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Hour)
	earliest := now.Add(-time.Duration(hours-1) * time.Hour).Unix()
	out := make([]storageSample, 0)
	for key, sample := range a.storage {
		if key.Bucket == bucket && key.Hour >= earliest && key.Hour <= now.Unix() {
			out = append(out, sample)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour < out[j].Hour })
	return out
}
