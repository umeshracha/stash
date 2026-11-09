package server

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/csv"
	"errors"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const adminPath = "/.stash/admin/"

//go:embed web/admin.html
var adminHTML string

var adminTemplate = template.Must(template.New("console").Parse(adminHTML))

type adminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type adminConsole struct {
	config    adminConfig
	analytics *analytics
}

type bucketUsage struct {
	StoredBytes                 uint64
	Name, Link, Current, Stored string
	Objects, Versions, Markers  int
}

type objectLink struct{ Key, URL, Size, Modified string }

type dashboardRow struct {
	Hour, Bucket, App, Operation, Requests, Errors, Uploaded, Downloaded, P95 string
}

type trafficBar struct {
	Label    string
	Requests uint64
	Percent  int
}

type storageBar struct {
	Label, Size string
	Percent     int
}
type dashboard struct {
	StoredBytes                                           uint64
	Storage                                               []storageBar
	Traffic                                               []trafficBar
	DiskUsed, DiskFree, Stored, ErrorRate, P95            string
	Requests                                              uint64
	Buckets                                               []bucketUsage
	Objects                                               []objectLink
	Rows                                                  []dashboardRow
	Bucket, Prefix, App, Operation, CSV, StorageCSV, Next string
	Hours                                                 int
	Showing                                               int
	TotalRows                                             int
	Truncated                                             bool
	Replication                                           []replicationPanel
}

type replicationPanel struct {
	Bucket, State, LastSuccess, Error string
	Versions                          int
}

func formatInt(n int64) string    { return strconv.FormatInt(n, 10) }
func formatCount(n uint64) string { return strconv.FormatUint(n, 10) }

func byteCount(size uint64) string {
	const unit = 1024
	if size < unit {
		return formatCount(size) + " B"
	}
	value := float64(size)
	for _, label := range []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"} {
		value /= unit
		if value < unit || label == "EiB" {
			return strconv.FormatFloat(value, 'f', 1, 64) + " " + label
		}
	}
	return formatCount(size) + " B"
}

func (a *adminConsole) authenticate(w http.ResponseWriter, r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if r.TLS == nil && !loopback(host) {
		http.Error(w, "TLS is required for the admin console", 403)
		return false
	}
	user, password, ok := r.BasicAuth()
	u, wantUser := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(a.config.Username))
	p, wantPassword := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(a.config.Password))
	match := subtle.ConstantTimeCompare(u[:], wantUser[:]) & subtle.ConstantTimeCompare(p[:], wantPassword[:])
	if !ok || match != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="Stash administration", charset="UTF-8"`)
		http.Error(w, "Admin credentials required", 401)
		return false
	}
	return true
}

func (a *adminConsole) serve(w http.ResponseWriter, r *http.Request, s *server) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if !a.authenticate(w, r) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return
	}
	q := r.URL.Query()
	bucket, prefix, app, operation := q.Get("bucket"), q.Get("prefix"), q.Get("app"), q.Get("operation")
	if bucket != "" && !bucketName.MatchString(bucket) || len(prefix) > 1024 || len(app) > 64 || len(operation) > 40 {
		http.Error(w, "Invalid filter", 400)
		return
	}
	hours := 24
	if q.Has("hours") {
		var err error
		hours, err = strconv.Atoi(q.Get("hours"))
		if err != nil || hours < 1 || hours > 720 {
			http.Error(w, "Invalid time range", 400)
			return
		}
	}
	switch r.URL.Path {
	case adminPath + "download":
		a.download(w, r, s, bucket, q.Get("key"))
	case adminPath + "storage.csv":
		writeStorageCSV(w, a.analytics.storageSeries(bucket, hours))
	case adminPath + "analytics.csv":
		writeAnalyticsCSV(w, a.analytics.selectRows(bucket, app, operation, hours))
	case adminPath:
		rows := a.analytics.selectRows(bucket, app, operation, hours)
		page := dashboard{Bucket: bucket, Prefix: prefix, App: app, Operation: operation, Hours: hours,
			CSV: adminPath + "analytics.csv?" + q.Encode(), StorageCSV: adminPath + "storage.csv?" + q.Encode(), TotalRows: len(rows)}
		if err := scanDashboard(s.store, &page, q.Get("after")); err != nil {
			http.Error(w, "Storage inventory unavailable", 503)
			return
		}
		if s.replication != nil {
			s.replication.mu.RLock()
			for name, status := range s.replication.status {
				state := "Synchronized"
				if status.LastError != "" {
					state = "Retrying"
				} else if status.LastSuccess.IsZero() {
					state = "Starting"
				}
				item := replicationPanel{Bucket: name, State: state, Versions: status.Versions, Error: status.LastError}
				if !status.LastSuccess.IsZero() {
					item.LastSuccess = status.LastSuccess.UTC().Format(time.RFC3339)
				}
				page.Replication = append(page.Replication, item)
			}
			s.replication.mu.RUnlock()
			sort.Slice(page.Replication, func(i, j int) bool { return page.Replication[i].Bucket < page.Replication[j].Bucket })
		}
		var all analyticsRow
		for i, row := range rows {
			all.Requests += row.Requests
			all.Errors += row.Errors
			for index, count := range row.Latency {
				all.Latency[index] += count
			}
			if i < 100 {
				page.Rows = append(page.Rows, dashboardRow{
					time.Unix(row.Hour, 0).UTC().Format("Jan 02 15:04"), row.Bucket, row.App, row.Operation,
					formatCount(row.Requests), formatCount(row.Errors), byteCount(row.Uploaded), byteCount(row.Downloaded), row.p95(),
				})
			}
		}
		page.Traffic = trafficBars(rows, hours, time.Now())
		page.Storage = storageBars(a.analytics.storageSeries(bucket, hours))
		page.Showing = len(page.Rows)
		page.Requests = all.Requests
		page.ErrorRate = "0%"
		page.P95 = "—"
		if all.Requests > 0 {
			page.ErrorRate = strconv.FormatFloat(100*float64(all.Errors)/float64(all.Requests), 'f', 1, 64) + "%"
			page.P95 = all.p95() + " ms"
		}
		if page.Next != "" {
			next := r.URL.Query()
			next.Set("after", page.Next)
			page.Next = adminPath + "?" + next.Encode()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		adminTemplate.Execute(w, page)
	default:
		http.NotFound(w, r)
	}
}

func scanDashboard(s *store, page *dashboard, after string) error {
	var disk syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &disk); err == nil {
		page.DiskFree = byteCount(uint64(disk.Bavail) * uint64(disk.Bsize))
		page.DiskUsed = byteCount((uint64(disk.Blocks) - uint64(disk.Bfree)) * uint64(disk.Bsize))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var total uint64
	var objects []object
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !bucketName.MatchString(name) {
			continue
		}
		dir := filepath.Join(s.dir, name)
		if errors.Is(checkReplicaCheckpoint(dir), errReplicaDirty) {
			continue
		}
		names, err := versionNames(dir)
		if err != nil {
			return err
		}
		usage := bucketUsage{Name: name, Link: adminPath + "?" + url.Values{"bucket": {name}}.Encode()}
		var current, stored uint64
		for _, hash := range names {
			versions, err := versionsFor(dir, hash)
			if err != nil {
				return err
			}
			for i, version := range versions {
				if version.DeleteMarker {
					usage.Markers++
					continue
				}
				usage.Versions++
				stored += uint64(version.Size)
				if i == 0 {
					usage.Objects++
					current += uint64(version.Size)
					if name == page.Bucket && strings.HasPrefix(version.Key, page.Prefix) && version.Key > after {
						objects = append(objects, version.object)
					}
				}
			}
		}
		total += stored
		usage.Current, usage.Stored = byteCount(current), byteCount(stored)
		usage.StoredBytes = stored
		page.Buckets = append(page.Buckets, usage)
	}
	page.Stored = byteCount(total)
	page.StoredBytes = total
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	page.Truncated = len(objects) > 100
	for _, obj := range objects[:min(len(objects), 100)] {
		link := adminPath + "download?" + url.Values{"bucket": {page.Bucket}, "key": {obj.Key}}.Encode()
		page.Objects = append(page.Objects, objectLink{obj.Key, link, byteCount(uint64(obj.Size)), obj.Modified.UTC().Format(time.RFC3339)})
		page.Next = obj.Key
	}
	if !page.Truncated {
		page.Next = ""
	}
	return nil
}

func (a *adminConsole) download(w http.ResponseWriter, r *http.Request, s *server, bucket, key string) {
	if bucket == "" || !validKey(key) {
		http.Error(w, "Invalid object", 400)
		return
	}
	s.store.mu.RLock()
	s.store.versionMu.RLock()
	file, obj, err := s.store.openVersion(filepath.Join(s.store.dir, bucket), digest(key), "")
	s.store.versionMu.RUnlock()
	s.store.mu.RUnlock()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Object unavailable", 503)
		}
		return
	}
	if obj.DeleteMarker {
		file.Close()
		http.NotFound(w, r)
		return
	}
	data, err := s.store.objectData(file, obj)
	if err != nil {
		http.Error(w, "Object data unavailable", 503)
		return
	}
	defer data.Close()
	name := filepath.Base(key)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("ETag", obj.ETag)
	http.ServeContent(w, r, "", obj.Modified, io.NewSectionReader(data, 0, obj.Size))
}

func writeAnalyticsCSV(w http.ResponseWriter, rows []analyticsRow) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="stash-analytics.csv"`)
	out := csv.NewWriter(w)
	out.Write([]string{"hour_utc", "bucket", "app", "operation", "requests", "errors", "upload_wire_bytes", "download_bytes", "p95_ms_upper_bound"})
	for _, row := range rows {
		app := row.App
		if trimmed := strings.TrimLeftFunc(app, unicode.IsSpace); trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
			app = "'" + app
		}
		out.Write([]string{time.Unix(row.Hour, 0).UTC().Format(time.RFC3339), row.Bucket, app, row.Operation, formatCount(row.Requests),
			formatCount(row.Errors), formatCount(row.Uploaded), formatCount(row.Downloaded), row.p95()})
	}
	out.Flush()
}

func trafficBars(rows []analyticsRow, hours int, now time.Time) []trafficBar {
	groupHours := (hours + 23) / 24
	groups := (hours + groupHours - 1) / groupHours
	bars := make([]trafficBar, groups)
	start := now.UTC().Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour)
	step := int64(groupHours * 3600)
	for i := range bars {
		bars[i].Label = start.Add(time.Duration(i*groupHours) * time.Hour).Format("Jan 02 15:04")
	}
	var peak uint64
	for _, row := range rows {
		index := (row.Hour - start.Unix()) / step
		if row.Hour < start.Unix() || index >= int64(groups) {
			continue
		}
		bars[index].Requests += row.Requests
		peak = max(peak, bars[index].Requests)
	}
	if peak != 0 {
		for i := range bars {
			if bars[i].Requests > 0 {
				bars[i].Percent = max(2, int(100*float64(bars[i].Requests)/float64(peak)))
			}
		}
	}
	return bars
}

func storageBars(samples []storageSample) []storageBar {
	group := (len(samples) + 23) / 24
	if group == 0 {
		return nil
	}
	bars := make([]storageBar, 0, 24)
	var maxSize uint64
	for i := group - 1; i < len(samples); i += group {
		maxSize = max(maxSize, samples[i].Bytes)
	}
	maxSize = max(maxSize, samples[len(samples)-1].Bytes)
	for start := 0; start < len(samples); start += group {
		sample := samples[min(len(samples)-1, start+group-1)]
		percent := 0
		if sample.Bytes > 0 {
			percent = max(2, int(100*float64(sample.Bytes)/float64(maxSize)))
		}
		bars = append(bars, storageBar{time.Unix(sample.Hour, 0).UTC().Format("Jan 02 15:04"), byteCount(sample.Bytes), percent})
	}
	return bars
}

func writeStorageCSV(w http.ResponseWriter, samples []storageSample) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="stash-storage.csv"`)
	out := csv.NewWriter(w)
	out.Write([]string{"hour_utc", "bucket", "stored_bytes"})
	for _, sample := range samples {
		out.Write([]string{time.Unix(sample.Hour, 0).UTC().Format(time.RFC3339), sample.Bucket, formatCount(sample.Bytes)})
	}
	out.Flush()
}
