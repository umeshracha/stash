package server

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

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
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

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
	if cfg.Admin != nil && (cfg.Admin.Username == "" || strings.Contains(cfg.Admin.Username, ":") || len(cfg.Admin.Password) < 16) {
		return cfg, fmt.Errorf("admin console requires a username and password of at least 16 bytes")
	}
	for id, c := range cfg.Credentials {
		if id == "" || len(c.Secret) < 16 || len(c.Label) > 64 {
			return cfg, fmt.Errorf("each credential needs an ID and a secret of at least 16 bytes")
		}
		for bucket, permission := range c.Buckets {
			if (bucket != "*" && !bucketName.MatchString(bucket)) || (permission != "read" && permission != "write" && permission != "admin") {
				return cfg, fmt.Errorf("invalid bucket grant for %q", id)
			}
		}
	}
	return cfg, nil
}
