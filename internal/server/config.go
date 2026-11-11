package server

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"stash/internal/encryption"
	"stash/internal/erasure"
)

type config struct {
	Encryption         *encryption.Config       `json:"encryption"`
	AuditLog           bool                     `json:"audit_log"`
	Policies           map[string]accessPolicy  `json:"policies"`
	Admin              *adminConfig             `json:"admin"`
	Cluster            *clusterConfig           `json:"cluster"`
	ShardNodeToken     string                   `json:"shard_node_token"`
	Erasure            *erasure.Config          `json:"erasure"`
	ReplicationExports map[string]string        `json:"replication_exports"`
	ReplicaBuckets     map[string]replicaSource `json:"replica_buckets"`
	PromoteBuckets     []string                 `json:"promote_buckets"`
	Listen             string                   `json:"listen"`
	DataDir            string                   `json:"data_dir"`
	Region             string                   `json:"region"`
	Cert               string                   `json:"tls_cert"`
	Key                string                   `json:"tls_key"`
	Credentials        map[string]credential    `json:"credentials"`
	BodyIdleTimeout    int                      `json:"body_idle_timeout_seconds"`
}

// defaultBodyIdle is how long a request body may deliver nothing before the
// request is ended. Amazon S3 allows 20 seconds; this is deliberately looser.
const defaultBodyIdle = 2 * time.Minute

func (c config) bodyIdle() time.Duration {
	if c.BodyIdleTimeout == 0 {
		return defaultBodyIdle
	}
	return time.Duration(c.BodyIdleTimeout) * time.Second
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// samplePrefix starts every placeholder secret in stash.example.json. They are long
// enough to pass the length check and are public, so a server must refuse to start with one.
const samplePrefix = "replace-this"

func isSample(secret string) bool {
	return strings.HasPrefix(strings.ToLower(secret), samplePrefix)
}

func loadConfig(path string) (config, error) {
	var cfg config
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	cfg = config{Listen: "127.0.0.1:9000", DataDir: "stash-data", Region: "us-east-1"}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.Listen == "" || cfg.DataDir == "" || cfg.Region == "" || len(cfg.Credentials) == 0 && cfg.ShardNodeToken == "" || (cfg.Cert == "") != (cfg.Key == "") {
		return cfg, fmt.Errorf("configure listen, data_dir, region, credentials, and both TLS files when enabling TLS")
	}
	if cfg.BodyIdleTimeout < 0 || cfg.BodyIdleTimeout > 86400 {
		return cfg, fmt.Errorf("body_idle_timeout_seconds must be from 1 to 86400, or omitted for the default")
	}
	if cfg.Admin != nil && (cfg.Admin.Username == "" || strings.Contains(cfg.Admin.Username, ":") || len(cfg.Admin.Password) < 16) {
		return cfg, fmt.Errorf("admin console requires a username and password of at least 16 bytes")
	}
	if cfg.Admin != nil && isSample(cfg.Admin.Password) {
		return cfg, fmt.Errorf("the admin console password is still a sample value: replace it with a unique random password")
	}
	for id, c := range cfg.Credentials {
		if id == "" || len(c.Secret) < 16 || len(c.Label) > 64 {
			return cfg, fmt.Errorf("each credential needs an ID and a secret of at least 16 bytes")
		}
		if isSample(c.Secret) {
			return cfg, fmt.Errorf("credential %q still has a sample secret from stash.example.json: replace it with a unique random secret", id)
		}
		for bucket, permission := range c.Buckets {
			if (bucket != "*" && !bucketName.MatchString(bucket)) || (permission != "read" && permission != "write" && permission != "admin") {
				return cfg, fmt.Errorf("invalid bucket grant for %q", id)
			}
		}
	}
	return cfg, nil
}
