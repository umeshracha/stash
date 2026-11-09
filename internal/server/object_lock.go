package server

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const objectLockFile = ".object-lock"
const objectLockPrefix = ".ol-"

var errObjectProtected = errors.New("object version is protected")
var errObjectLockDisabled = errors.New("object lock is disabled")

type objectRetention struct {
	Mode  string    `xml:",omitempty"`
	Until time.Time `xml:"RetainUntilDate"`
}

type objectProtection struct {
	Retention objectRetention
	LegalHold bool
}

type defaultRetention struct {
	Mode  string
	Days  int `xml:",omitempty"`
	Years int `xml:",omitempty"`
}

type lockConfiguration struct {
	XMLName xml.Name                                     `xml:"ObjectLockConfiguration" json:"-"`
	XMLNS   string                                       `xml:"xmlns,attr,omitempty" json:"-"`
	Enabled string                                       `xml:"ObjectLockEnabled"`
	Rule    *struct{ DefaultRetention defaultRetention } `xml:",omitempty"`
}

func readLockConfig(dir string) (*lockConfiguration, error) {
	body, err := os.ReadFile(filepath.Join(dir, objectLockFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var config lockConfiguration
	if err := json.Unmarshal(body, &config); err != nil || !validLockConfig(config) {
		return nil, errors.New("invalid stored object lock configuration")
	}
	return &config, nil
}

func validRetentionMode(mode string) bool { return mode == "GOVERNANCE" || mode == "COMPLIANCE" }

func validLockConfig(config lockConfiguration) bool {
	if config.Enabled != "Enabled" {
		return false
	}
	if config.Rule == nil {
		return true
	}
	rule := config.Rule.DefaultRetention
	return validRetentionMode(rule.Mode) && (rule.Days > 0 && rule.Days <= 36500 && rule.Years == 0 ||
		rule.Years > 0 && rule.Years <= 100 && rule.Days == 0)
}

func writeLockConfig(dir string, config lockConfiguration) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return writeMetadataFile(dir, objectLockFile, data)
}

func lockXML(w http.ResponseWriter, r *http.Request, value any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil || xml.Unmarshal(body, value) != nil {
		failure(w, 400, "MalformedXML")
		return false
	}
	if r.Header.Get("X-Amz-Content-Sha256") != "UNSIGNED-PAYLOAD" && r.Header.Get("X-Amz-Content-Sha256") != digest(string(body)) {
		failure(w, 400, "BadDigest")
		return false
	}
	for name := range r.Header {
		switch name {
		case "Content-Md5", "X-Amz-Checksum-Crc32", "X-Amz-Checksum-Crc32c", "X-Amz-Checksum-Crc64nvme", "X-Amz-Checksum-Sha1", "X-Amz-Checksum-Sha256":
			if !validDeleteChecksum(r, body) {
				failure(w, 400, "BadDigest")
				return false
			}
			return true
		}
	}
	return true
}

func (s *server) bucketLock(w http.ResponseWriter, r *http.Request, bucket string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	if _, err := os.Stat(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	if r.Method == http.MethodGet {
		config, err := readLockConfig(dir)
		if err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		if config == nil {
			failure(w, 404, "ObjectLockConfigurationNotFoundError")
			return
		}
		config.XMLNS = s3Namespace
		respond(w, 200, config)
		return
	}
	var config lockConfiguration
	if !lockXML(w, r, &config) {
		return
	}
	if !validLockConfig(config) {
		failure(w, 400, "InvalidRequest")
		return
	}
	status, err := versionStatus(dir)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	if status != "Enabled" {
		failure(w, 409, "InvalidBucketState")
		return
	}
	if err := writeLockConfig(dir, config); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	w.WriteHeader(200)
}

func protectionPath(dir, name, id string) string {
	return filepath.Join(dir, objectLockPrefix+name+"-"+id)
}

func loadProtection(dir, name string, obj *object) error {
	data, err := os.ReadFile(protectionPath(dir, name, obj.VersionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var protection objectProtection
	if err := json.Unmarshal(data, &protection); err != nil {
		return err
	}
	obj.Protection = &protection
	return nil
}

func (p *objectProtection) blocksDelete(now time.Time, bypass bool) bool {
	return p != nil && (p.LegalHold || p.Retention.Until.After(now) &&
		(p.Retention.Mode != "GOVERNANCE" || !bypass))
}

func (s *server) bypassGovernance(r *http.Request, c credential, bucket, key string) bool {
	return r.Header.Get("X-Amz-Bypass-Governance-Retention") == "true" &&
		s.allows(c, "s3:BypassGovernanceRetention", bucket, key, nil)
}

func (s *server) versionProtection(w http.ResponseWriter, r *http.Request, c credential, bucket, key, version string, legal bool) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	config, err := readLockConfig(dir)
	if err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	if config == nil {
		failure(w, 400, "InvalidRequest")
		return
	}
	name := digest(key)
	file, obj, err := s.store.openVersion(dir, name, version)
	if err != nil {
		storageError(w, err, "NoSuchVersion")
		return
	}
	file.Close()
	if obj.DeleteMarker {
		failure(w, 405, "MethodNotAllowed")
		return
	}
	var current objectProtection
	if obj.Protection != nil {
		current = *obj.Protection
	}
	type legalRequest struct {
		XMLName xml.Name `xml:"LegalHold"`
		XMLNS   string   `xml:"xmlns,attr,omitempty"`
		Status  string
	}
	type retentionRequest struct {
		XMLName xml.Name   `xml:"Retention"`
		XMLNS   string     `xml:"xmlns,attr,omitempty"`
		Mode    string     `xml:",omitempty"`
		Until   *time.Time `xml:"RetainUntilDate,omitempty"`
	}
	if r.Method == http.MethodGet {
		if legal {
			status := "OFF"
			if current.LegalHold {
				status = "ON"
			}
			respond(w, 200, legalRequest{XMLNS: s3Namespace, Status: status})
		} else {
			value := retentionRequest{XMLNS: s3Namespace, Mode: current.Retention.Mode}
			if !current.Retention.Until.IsZero() {
				value.Until = &current.Retention.Until
			}
			respond(w, 200, value)
		}
		return
	}
	if legal {
		var request legalRequest
		if !lockXML(w, r, &request) {
			return
		}
		if request.Status != "ON" && request.Status != "OFF" {
			failure(w, 400, "InvalidArgument")
			return
		}
		current.LegalHold = request.Status == "ON"
	} else {
		var request retentionRequest
		if !lockXML(w, r, &request) {
			return
		}
		now := time.Now()
		retention := objectRetention{}
		if request.Until != nil {
			if !request.Until.After(now) || !validRetentionMode(request.Mode) {
				failure(w, 400, "InvalidArgument")
				return
			}
			retention = objectRetention{Mode: request.Mode, Until: request.Until.UTC()}
		} else if request.Mode != "" {
			failure(w, 400, "InvalidArgument")
			return
		}
		old := current.Retention
		if old.Until.After(now) {
			switch old.Mode {
			case "COMPLIANCE":
				if retention.Mode != "COMPLIANCE" || retention.Until.Before(old.Until) {
					failure(w, 403, "AccessDenied")
					return
				}
			case "GOVERNANCE":
				if (retention.Until.Before(old.Until) || retention.Mode != old.Mode) &&
					!s.bypassGovernance(r, c, bucket, key) {
					failure(w, 403, "AccessDenied")
					return
				}
			}
		}
		current.Retention = retention
	}
	data, err := json.Marshal(current)
	if err == nil {
		err = writeMetadataFile(dir, filepath.Base(protectionPath(dir, name, obj.VersionID)), data)
	}
	if err != nil {
		s.store.resetReplicaFeed(dir)
		storageError(w, err, "NoSuchVersion")
		return
	}
	obj.Protection = &current
	s.store.recordReplicaChange(dir, obj, false)
	w.WriteHeader(200)
}

func applyDefaultLock(dir string, obj *object) error {
	if obj.DeleteMarker {
		return nil
	}
	config, err := readLockConfig(dir)
	if err != nil {
		return err
	}
	if config == nil {
		if obj.Protection != nil {
			return errObjectLockDisabled
		}
		return nil
	}
	if config.Rule != nil {
		if obj.Protection == nil {
			obj.Protection = &objectProtection{}
		}
		if obj.Protection.Retention.Mode == "" {
			rule := config.Rule.DefaultRetention
			obj.Protection.Retention = objectRetention{Mode: rule.Mode, Until: time.Now().UTC().AddDate(rule.Years, 0, rule.Days)}
		}
	}
	return nil
}

type uploadProtectionContext struct{}

func (s *server) protectUpload(w http.ResponseWriter, r *http.Request, c credential, bucket, key string) (*http.Request, bool) {
	mode := r.Header.Get("X-Amz-Object-Lock-Mode")
	until := r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")
	hold := r.Header.Get("X-Amz-Object-Lock-Legal-Hold")
	if mode == "" && until == "" && hold == "" {
		return r, true
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost ||
		r.URL.Query().Has("uploadId") || r.Method == http.MethodPost && !r.URL.Query().Has("uploads") {
		failure(w, 400, "InvalidRequest")
		return r, false
	}
	p := &objectProtection{}
	if mode != "" || until != "" {
		when, err := time.Parse(time.RFC3339, until)
		if err != nil || !when.After(time.Now()) || !validRetentionMode(mode) {
			failure(w, 400, "InvalidArgument")
			return r, false
		}
		if !s.allows(c, "s3:PutObjectRetention", bucket, key, nil) {
			failure(w, 403, "AccessDenied")
			return r, false
		}
		p.Retention = objectRetention{Mode: mode, Until: when.UTC()}
	}
	if hold != "" {
		if hold != "ON" && hold != "OFF" {
			failure(w, 400, "InvalidArgument")
			return r, false
		}
		if !s.allows(c, "s3:PutObjectLegalHold", bucket, key, nil) {
			failure(w, 403, "AccessDenied")
			return r, false
		}
		p.LegalHold = hold == "ON"
	}
	return r.WithContext(context.WithValue(r.Context(), uploadProtectionContext{}, p)), true
}

func requestedProtection(r *http.Request) *objectProtection {
	protection, _ := r.Context().Value(uploadProtectionContext{}).(*objectProtection)
	return protection
}

func createLockedBucket(root, path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.MkdirTemp(root, ".start-locked-bucket-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := writeMetadataFile(tmp, versionConfig, []byte("Enabled")); err != nil {
		return err
	}
	if err := writeLockConfig(tmp, lockConfiguration{Enabled: "Enabled"}); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
