package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const bucketPolicyFile = ".bucket-policy"
const maxBucketPolicy = 20 << 10

type bucketPolicy struct {
	Version   string
	Statement []bucketPolicyStatement
}
type bucketPolicyStatement struct {
	policyStatement
	Principal struct{ AWS policyStrings }
}

func decodeBucketPolicy(body []byte, bucket string, credentials map[string]credential) (bucketPolicy, error) {
	var policy bucketPolicy
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return policy, errors.New("trailing policy data")
	}
	rules := accessPolicy{Version: policy.Version}
	for _, statement := range policy.Statement {
		rules.Statement = append(rules.Statement, statement.policyStatement)
		if len(statement.Principal.AWS) == 0 || len(statement.Principal.AWS) > 100 {
			return policy, errors.New("missing or invalid principal")
		}
		for _, id := range statement.Principal.AWS {
			if _, ok := credentials[id]; id == "*" || !ok {
				return policy, errors.New("principal must be an existing local access key")
			}
		}
		for _, resource := range statement.Resource {
			if resource != s3ARN+bucket && !strings.HasPrefix(resource, s3ARN+bucket+"/") {
				return policy, errors.New("bucket policy resource must belong to its bucket")
			}
		}
	}
	return policy, validateAccessPolicy(rules)
}

func (s *server) allows(c credential, action, bucket, key string, prefix *string) bool {
	if strings.HasSuffix(action, "BucketPolicy") || !strings.HasPrefix(action, "s3:") {
		return c.allows(action, bucket, key, prefix)
	}
	resource := s3ARN + bucket
	if key != "" {
		resource += "/" + key
	}
	allow, deny := c.policyDecision(action, resource, prefix)
	if deny {
		return false
	}
	allow = allow || legacyAllows(c.permission(bucket), action)
	body, err := os.ReadFile(filepath.Join(s.store.dir, bucket, bucketPolicyFile))
	if errors.Is(err, os.ErrNotExist) {
		return allow
	}
	if err != nil || len(body) > maxBucketPolicy {
		return false
	}
	// A principal removed from the current configuration no longer authenticates.
	// Preserve rules for any remaining principals when a credential is rotated.
	var policy bucketPolicy
	if json.Unmarshal(body, &policy) != nil {
		return false
	}
	for _, rule := range policy.Statement {
		if !slices.Contains(rule.Principal.AWS, c.id) || !rule.matches(action, resource, prefix) {
			continue
		}
		if rule.Effect == "Deny" {
			return false
		}
		if rule.Effect == "Allow" {
			allow = true
		}
	}
	return allow
}

func (s *server) bucketPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	dir := filepath.Join(s.store.dir, bucket)
	if _, err := os.Stat(dir); err != nil {
		storageError(w, err, "NoSuchBucket")
		return
	}
	path := filepath.Join(dir, bucketPolicyFile)
	switch r.Method {
	case http.MethodGet:
		body, err := os.ReadFile(path)
		if err != nil {
			storageError(w, err, "NoSuchBucketPolicy")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBucketPolicy))
		if err != nil {
			failure(w, 400, "MalformedPolicy")
			return
		}
		if payload := r.Header.Get("X-Amz-Content-Sha256"); payload != "UNSIGNED-PAYLOAD" && payload != digest(string(body)) {
			failure(w, 400, "BadDigest")
			return
		}
		if _, err := decodeBucketPolicy(body, bucket, s.credentials); err != nil {
			failure(w, 400, "MalformedPolicy")
			return
		}
		if err := writeMetadataFile(dir, bucketPolicyFile, body); err != nil {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(204)
	case http.MethodDelete:
		err := os.Remove(path)
		if err == nil {
			err = syncDir(dir)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			storageError(w, err, "NoSuchBucket")
			return
		}
		w.WriteHeader(204)
	default:
		failure(w, 501, "NotImplemented")
	}
}
