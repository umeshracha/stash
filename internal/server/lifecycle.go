package server

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"stash/internal/erasure"
	"stash/internal/etcd"
	"stash/internal/fsutil"
)

const lifecycleFile = ".lifecycle"

type lifecycleConfig struct {
	XMLName xml.Name        `xml:"LifecycleConfiguration"`
	Rules   []lifecycleRule `xml:"Rule"`
}

type lifecycleRule struct {
	ID         string
	Status     string
	Prefix     *string
	Filter     *struct{ Prefix string }
	Expiration *struct {
		Days                      int
		Date                      *time.Time
		ExpiredObjectDeleteMarker *bool
	}
	NoncurrentVersionExpiration    *struct{ NoncurrentDays, NewerNoncurrentVersions int }
	AbortIncompleteMultipartUpload *struct{ DaysAfterInitiation int }
}

// Check the schema before decoding because encoding/xml ignores unknown fields.
var lifecycleElements = map[string][]string{
	"LifecycleConfiguration":         {"Rule"},
	"Rule":                           {"ID", "Status", "Prefix", "Filter", "Expiration", "NoncurrentVersionExpiration", "AbortIncompleteMultipartUpload"},
	"Filter":                         {"Prefix"},
	"Expiration":                     {"Days", "Date", "ExpiredObjectDeleteMarker"},
	"NoncurrentVersionExpiration":    {"NoncurrentDays", "NewerNoncurrentVersions"},
	"AbortIncompleteMultipartUpload": {"DaysAfterInitiation"},
}

func parseLifecycle(data []byte) (lifecycleConfig, error) {
	var config lifecycleConfig
	type element struct {
		name     string
		children map[string]bool
	}
	var stack []element
	root := false
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return config, err
		}
		switch item := token.(type) {
		case xml.StartElement:
			name := item.Name.Local
			for _, attr := range item.Attr {
				if attr.Name.Local != "xmlns" || attr.Name.Space != "" || attr.Value != s3Namespace {
					return config, errors.New("unsupported lifecycle attribute")
				}
			}
			if item.Name.Space != "" && item.Name.Space != s3Namespace {
				return config, errors.New("unsupported lifecycle namespace")
			}
			if len(stack) == 0 {
				if root || name != "LifecycleConfiguration" {
					return config, errors.New("invalid lifecycle root")
				}
				root = true
			} else {
				parent := &stack[len(stack)-1]
				allowed := false
				for _, child := range lifecycleElements[parent.name] {
					if child == name {
						allowed = true
						break
					}
				}
				if !allowed || parent.children[name] && name != "Rule" {
					return config, errors.New("unsupported or duplicate lifecycle element")
				}
				parent.children[name] = true
			}
			stack = append(stack, element{name: name, children: map[string]bool{}})
		case xml.EndElement:
			if len(stack) == 0 {
				return config, errors.New("invalid lifecycle XML")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if (len(stack) == 0 || lifecycleElements[stack[len(stack)-1].name] != nil) && strings.TrimSpace(string(item)) != "" {
				return config, errors.New("invalid lifecycle text")
			}
		}
	}
	if err := xml.Unmarshal(data, &config); err != nil {
		return config, err
	}
	if len(config.Rules) == 0 || len(config.Rules) > 1000 {
		return config, errors.New("invalid lifecycle rule count")
	}
	ids := map[string]bool{}
	for _, rule := range config.Rules {
		if rule.Status != "Enabled" && rule.Status != "Disabled" || len(rule.ID) > 255 || rule.ID != "" && ids[rule.ID] ||
			rule.Prefix != nil && rule.Filter != nil || len(rule.prefix()) > 1024 ||
			rule.Expiration == nil && rule.NoncurrentVersionExpiration == nil && rule.AbortIncompleteMultipartUpload == nil {
			return config, errors.New("invalid lifecycle rule")
		}
		ids[rule.ID] = true
		if expiration := rule.Expiration; expiration != nil {
			fields := 0
			if expiration.Days != 0 {
				if !validLifecycleDays(expiration.Days) {
					return config, errors.New("invalid expiration days")
				}
				fields++
			}
			if expiration.Date != nil {
				date := expiration.Date.UTC()
				if !date.Equal(date.Truncate(24 * time.Hour)) {
					return config, errors.New("expiration date must be midnight UTC")
				}
				fields++
			}
			if expiration.ExpiredObjectDeleteMarker != nil {
				fields++
			}
			if fields != 1 {
				return config, errors.New("specify one expiration action")
			}
		}
		if older := rule.NoncurrentVersionExpiration; older != nil && (!validLifecycleDays(older.NoncurrentDays) ||
			older.NewerNoncurrentVersions < 0 || older.NewerNoncurrentVersions > 100 ||
			older.NewerNoncurrentVersions != 0 && rule.Filter == nil) {
			return config, errors.New("invalid noncurrent expiration")
		}
		if abort := rule.AbortIncompleteMultipartUpload; abort != nil && !validLifecycleDays(abort.DaysAfterInitiation) {
			return config, errors.New("invalid multipart expiration")
		}
	}
	return config, nil
}

func validLifecycleDays(days int) bool { return days > 0 && days <= 365000 }

func (r lifecycleRule) prefix() string {
	if r.Filter != nil {
		return r.Filter.Prefix
	}
	if r.Prefix != nil {
		return *r.Prefix
	}
	return ""
}

func (s *server) bucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	if _, err := os.Stat(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	path := filepath.Join(dir, lifecycleFile)
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(path)
		if err != nil {
			storageError(w, err, "NoSuchLifecycleConfiguration")
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Write(data)
	case http.MethodPut:
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMetadata))
		if err != nil {
			failure(w, 400, "MalformedXML")
			return
		}
		hash := r.Header.Get("X-Amz-Content-Sha256")
		if hash != "UNSIGNED-PAYLOAD" && hash != digest(string(data)) {
			failure(w, 400, "BadDigest")
			return
		}
		if _, err := parseLifecycle(data); err != nil {
			failure(w, 400, "InvalidRequest")
			return
		}
		if err := fsutil.WriteFileAtomic(dir, lifecycleFile, data); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(200)
	case http.MethodDelete:
		err := os.Remove(path)
		if err == nil {
			err = fsutil.SyncDir(dir)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(204)
	}
}

func lifecycleDue(now, created time.Time, days int) bool {
	deadline := created.UTC().AddDate(0, 0, days)
	midnight := deadline.Truncate(24 * time.Hour)
	if !deadline.Equal(midnight) {
		midnight = midnight.Add(24 * time.Hour)
	}
	return !now.Before(midnight)
}

func (s *store) applyLifecycle(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	buckets, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, entry := range buckets {
		if !entry.IsDir() || !bucketName.MatchString(entry.Name()) {
			continue
		}
		count, err := s.applyBucketLifecycle(now, entry.Name())
		changed += count
		if err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// Callers serialize lifecycle changes with S3 requests.
func (s *store) applyBucketLifecycle(now time.Time, bucket string) (int, error) {
	dir := filepath.Join(s.dir, bucket)
	raw, err := os.ReadFile(filepath.Join(dir, lifecycleFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	replica, err := readReplicaStatus(dir)
	if err == nil && !replica.Promoted {
		return 0, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	config, err := parseLifecycle(raw)
	if err != nil {
		return 0, err
	}
	return s.expireBucket(dir, config.Rules, now)
}

func (s *store) expireBucket(dir string, rules []lifecycleRule, now time.Time) (int, error) {
	names, err := versionNames(dir)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, name := range names {
		versions, err := versionsFor(dir, name)
		if err != nil {
			return changed, err
		}
		if len(versions) == 0 {
			continue
		}
		newerObjects := 0
		for i, version := range versions {
			remove, current := false, i == 0
			for _, rule := range rules {
				if rule.Status != "Enabled" || !strings.HasPrefix(version.Key, rule.prefix()) {
					continue
				}
				if current && rule.Expiration != nil {
					exp := rule.Expiration
					if version.DeleteMarker {
						remove = remove || len(versions) == 1 && (exp.Days > 0 || exp.Date != nil ||
							exp.ExpiredObjectDeleteMarker != nil && *exp.ExpiredObjectDeleteMarker)
					} else {
						remove = remove || exp.Days > 0 && lifecycleDue(now, version.Modified, exp.Days) ||
							exp.Date != nil && !now.Before(*exp.Date)
					}
				}
				if !current && !version.DeleteMarker && rule.NoncurrentVersionExpiration != nil {
					exp := rule.NoncurrentVersionExpiration
					newerNoncurrent := max(0, newerObjects)
					if !versions[0].DeleteMarker {
						newerNoncurrent = max(0, newerNoncurrent-1)
					}
					remove = remove || newerNoncurrent >= exp.NewerNoncurrentVersions &&
						lifecycleDue(now, versions[i-1].Modified, exp.NoncurrentDays)
				}
			}
			if !version.DeleteMarker {
				newerObjects++
			}
			if !remove {
				continue
			}
			id := version.VersionID
			if current && !version.DeleteMarker {
				id = ""
			}
			_, err := s.removeVersion(dir, version.Key, id, false)
			if errors.Is(err, errObjectProtected) {
				continue
			}
			if err != nil {
				return changed, err
			}
			changed++
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return changed, err
	}
	for _, entry := range entries {
		id, ok := strings.CutPrefix(entry.Name(), ".mp-")
		if !ok || !entry.IsDir() || !erasure.ValidID(id) {
			continue
		}
		stage := filepath.Join(dir, entry.Name())
		path := filepath.Join(stage, "upload.json")
		body, err := os.ReadFile(path)
		if err != nil {
			return changed, err
		}
		info, err := decodeUploadInfo(body)
		if err != nil {
			return changed, err
		}
		if info.Created.IsZero() {
			stat, err := os.Stat(path)
			if err != nil {
				return changed, err
			}
			info.Created = stat.ModTime()
		}
		for _, rule := range rules {
			abort := rule.AbortIncompleteMultipartUpload
			if rule.Status == "Enabled" && abort != nil && strings.HasPrefix(info.Key, rule.prefix()) &&
				lifecycleDue(now, info.Created, abort.DaysAfterInitiation) {
				if err := discardUpload(dir, stage); err != nil {
					return changed, err
				}
				changed++
				break
			}
		}
	}
	return changed, nil
}

func runLifecycle(ctx context.Context, s *store, cluster *metadataCluster) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if err := lifecycleCycle(ctx, s, cluster); err != nil && ctx.Err() == nil {
			log.Printf("lifecycle sweep: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func lifecycleCycle(ctx context.Context, s *store, cluster *metadataCluster) error {
	if cluster == nil {
		_, err := s.applyLifecycle(time.Now().UTC())
		return err
	}
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	_, revision, err := cluster.refresh(ctx)
	if err != nil {
		return err
	}
	if cluster.partitioned {
		now := time.Now().UTC()
		for bucket := range cluster.partitions {
			count, err := s.applyBucketLifecycle(now, bucket)
			if err == nil && count != 0 {
				err = cluster.commitPartition(ctx, bucket, revision)
			}
			if err != nil {
				cluster.revision = ""
				return err
			}
		}
		return nil
	}
	count, err := s.applyLifecycle(time.Now().UTC())
	if err != nil {
		cluster.revision = ""
		return err
	}
	if count == 0 {
		return nil
	}
	data, err := snapshotMetadata(s.dir)
	if err == nil {
		cluster.revision, err = cluster.commit(ctx, revision, data)
	}
	if err != nil || cluster.revision == "" {
		cluster.revision = ""
		if err != nil {
			return err
		}
		return etcd.ErrQuorum
	}
	return nil
}
