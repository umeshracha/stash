package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

type policyStrings []string

func (v *policyStrings) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var single string
		if err := json.Unmarshal(data, &single); err != nil {
			return err
		}
		*v = []string{single}
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*v = values
	return nil
}

type accessPolicy struct {
	Version   string
	Statement []policyStatement
}

type policyStatement struct {
	Sid       string
	Effect    string
	Action    policyStrings
	Resource  policyStrings
	Condition map[string]map[string]policyStrings
}

const s3ARN = "arn:aws:s3:::"

func validateAccessPolicy(policy accessPolicy) error {
	if policy.Version != "" && policy.Version != "2012-10-17" || len(policy.Statement) == 0 || len(policy.Statement) > 100 {
		return errors.New("a policy needs 1–100 statements and version 2012-10-17 when specified")
	}
	for _, statement := range policy.Statement {
		if statement.Effect != "Allow" && statement.Effect != "Deny" ||
			len(statement.Action) == 0 || len(statement.Resource) == 0 || len(statement.Action) > 100 || len(statement.Resource) > 100 {
			return errors.New("invalid policy statement effect, action, or resource")
		}
		for _, action := range statement.Action {
			if action != "*" && !strings.HasPrefix(strings.ToLower(action), "s3:") || len(action) > 80 {
				return errors.New("policy actions must target S3")
			}
		}
		for _, resource := range statement.Resource {
			if resource != "*" && !strings.HasPrefix(resource, s3ARN) || len(resource) > 2048 {
				return errors.New("policy resources must be S3 ARNs or *")
			}
		}
		for operator, conditions := range statement.Condition {
			values, ok := conditions["s3:prefix"]
			if operator != "StringEquals" && operator != "StringLike" || !ok || len(conditions) != 1 || len(values) == 0 || len(values) > 100 {
				return errors.New("only StringEquals and StringLike for s3:prefix are supported")
			}
			for _, value := range values {
				if len(value) > 1024 {
					return errors.New("policy prefix exceeds 1024 bytes")
				}
			}
		}
	}
	return nil
}

func bindPolicies(cfg *config) error {
	for name, policy := range cfg.Policies {
		if name == "" {
			return errors.New("policy name must not be empty")
		}
		if err := validateAccessPolicy(policy); err != nil {
			return fmt.Errorf("policy %q: %w", name, err)
		}
	}
	for id, c := range cfg.Credentials {
		for _, name := range c.PolicyNames {
			policy, ok := cfg.Policies[name]
			if !ok {
				return fmt.Errorf("credential %q references unknown policy %q", id, name)
			}
			c.rules = append(c.rules, policy.Statement...)
			if len(c.rules) > 500 {
				return fmt.Errorf("credential %q has too many policy statements", id)
			}
		}
		cfg.Credentials[id] = c
	}
	return nil
}

// Wildcards match bytes, including slashes. Other characters are literal.
func policyGlob(pattern, value string) bool {
	var pi, vi int
	star, retry := -1, 0
	for vi < len(value) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi] && pattern[pi] != '*'):
			pi++
			vi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			pi++
			retry = vi
		case star >= 0:
			retry++
			vi = retry
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func (rule policyStatement) matches(action, resource string, prefix *string) bool {
	if !slices.ContainsFunc(rule.Action, func(pattern string) bool { return policyGlob(strings.ToLower(pattern), strings.ToLower(action)) }) ||
		!slices.ContainsFunc(rule.Resource, func(pattern string) bool { return policyGlob(pattern, resource) }) {
		return false
	}
	for operator, condition := range rule.Condition {
		if prefix == nil {
			return false
		}
		if !slices.ContainsFunc(condition["s3:prefix"], func(value string) bool {
			if operator == "StringEquals" {
				return value == *prefix
			}
			return policyGlob(value, *prefix)
		}) {
			return false
		}
	}
	return true
}

func (c credential) allows(action, bucket, key string, prefix *string) bool {
	resource := s3ARN + bucket
	if bucket == "" {
		resource = "*"
	}
	if key != "" {
		resource += "/" + key
	}
	allowed := legacyAllows(c.permission(bucket), action)
	if !strings.HasPrefix(action, "s3:") {
		return allowed
	}
	policyAllow, policyDeny := c.policyDecision(action, resource, prefix)
	return !policyDeny && (allowed || policyAllow)
}

func (c credential) policyDecision(action, resource string, prefix *string) (allowed, denied bool) {
	for _, rule := range c.rules {
		if !rule.matches(action, resource, prefix) {
			continue
		}
		if rule.Effect == "Deny" {
			return false, true
		}
		allowed = true
	}
	return allowed, false
}

func legacyAllows(grant, action string) bool {
	if grant == "" || action == "" {
		return false
	}
	switch action {
	case "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
		"s3:GetObject", "s3:GetObjectVersion":
		return true
	case "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts":
		return grant == "write" || grant == "admin"
	case "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketVersioning", "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketObjectLockConfiguration", "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration", "s3:GetObjectRetention", "s3:PutObjectRetention", "s3:GetObjectLegalHold", "s3:PutObjectLegalHold", "s3:BypassGovernanceRetention", "stash:GetReplicationStatus":
		return grant == "admin"
	}
	return false
}

func requestAction(r *http.Request) string {
	q := r.URL.Query()
	_, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if r.Method == http.MethodGet || r.Method == http.MethodPut {
		verb := "Get"
		if r.Method == http.MethodPut {
			verb = "Put"
		}
		switch {
		case key == "" && q.Has("object-lock"):
			return "s3:" + verb + "BucketObjectLockConfiguration"
		case key != "" && q.Has("retention"):
			return "s3:" + verb + "ObjectRetention"
		case key != "" && q.Has("legal-hold"):
			return "s3:" + verb + "ObjectLegalHold"
		}
	}
	switch s3Operation(r) {
	case "GetBucketLifecycleConfiguration":
		return "s3:GetLifecycleConfiguration"
	case "PutBucketLifecycleConfiguration", "DeleteBucketLifecycle":
		return "s3:PutLifecycleConfiguration"
	case "ListObjects", "HeadBucket":
		return "s3:ListBucket"
	case "ListObjectVersions":
		return "s3:ListBucketVersions"
	case "GetObject", "HeadObject":
		if r.URL.Query().Has("versionId") {
			return "s3:GetObjectVersion"
		}
		return "s3:GetObject"
	case "DeleteObject":
		if r.URL.Query().Has("versionId") {
			return "s3:DeleteObjectVersion"
		}
		return "s3:DeleteObject"
	case "PutObject", "CopyObject", "CreateMultipartUpload", "UploadPart", "UploadPartCopy", "CompleteMultipartUpload":
		return "s3:PutObject"
	case "ListParts":
		return "s3:ListMultipartUploadParts"
	case "AbortMultipartUpload", "CreateBucket", "DeleteBucket", "GetBucketLocation", "GetBucketVersioning", "PutBucketVersioning", "GetBucketPolicy", "PutBucketPolicy", "DeleteBucketPolicy":
		return "s3:" + s3Operation(r)
	}
	return ""
}
