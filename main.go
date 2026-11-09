package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type config struct {
	Encryption         *encryptionConfig        `json:"encryption"`
	AuditLog           bool                     `json:"audit_log"`
	Policies           map[string]accessPolicy  `json:"policies"`
	Admin              *adminConfig             `json:"admin"`
	Cluster            *clusterConfig           `json:"cluster"`
	ShardNodeToken     string                   `json:"shard_node_token"`
	Erasure            *erasureConfig           `json:"erasure"`
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

func main() {
	path := flag.String("config", "stash.json", "path to the JSON configuration")
	heal := flag.Bool("heal", false, "verify and repair erasure shards while the server is stopped")
	replacement := flag.Int("replace-erasure-drive", 0, "initialize replacement drive by its one-based index and heal while offline")
	lifecycleOnce := flag.Bool("lifecycle-once", false, "run one lifecycle expiration sweep and exit")
	rotateClusterKey := flag.Bool("rotate-cluster-key", false, "activate the configured encryption key through the cluster metadata quorum and exit")
	flag.Parse()
	if err := run(*path, *heal, *replacement, *lifecycleOnce, *rotateClusterKey); err != nil {
		log.Fatal(err)
	}
}

func run(path string, heal bool, replacement int, lifecycleOnce, rotateClusterKey bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	cfg := config{Listen: "127.0.0.1:9000", DataDir: "stash-data", Region: "us-east-1"}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return err
	}
	if cfg.Listen == "" || cfg.DataDir == "" || cfg.Region == "" || len(cfg.Credentials) == 0 && cfg.ShardNodeToken == "" || (cfg.Cert == "") != (cfg.Key == "") {
		return fmt.Errorf("configure listen, data_dir, region, credentials, and both TLS files when enabling TLS")
	}
	if cfg.Admin != nil && (cfg.Admin.Username == "" || strings.Contains(cfg.Admin.Username, ":") || len(cfg.Admin.Password) < 16) {
		return fmt.Errorf("admin console requires a username and password of at least 16 bytes")
	}
	for id, c := range cfg.Credentials {
		if id == "" || len(c.Secret) < 16 || len(c.Label) > 64 {
			return fmt.Errorf("each credential needs an ID and a secret of at least 16 bytes")
		}
		for bucket, permission := range c.Buckets {
			if (bucket != "*" && !bucketName.MatchString(bucket)) || (permission != "read" && permission != "write" && permission != "admin") {
				return fmt.Errorf("invalid bucket grant for %q", id)
			}
		}
	}
	if rotateClusterKey && (cfg.Cluster == nil || cfg.Encryption == nil || heal || replacement != 0 || lifecycleOnce) {
		return fmt.Errorf("key rotation requires an encrypted cluster configuration and its own command invocation")
	}
	if err := bindPolicies(&cfg); err != nil {
		return err
	}
	store, err := openStoreMode(cfg.DataDir, cfg.Cluster == nil && cfg.ShardNodeToken == "")
	if err != nil {
		return err
	}
	defer store.close()
	if cfg.ShardNodeToken != "" {
		if len(cfg.ShardNodeToken) < 24 || cfg.Erasure != nil || cfg.Encryption != nil || cfg.Cluster != nil || cfg.Admin != nil || cfg.AuditLog || len(cfg.Credentials) != 0 || heal || lifecycleOnce || replacement != 0 ||
			len(cfg.ReplicationExports) != 0 || len(cfg.ReplicaBuckets) != 0 || len(cfg.PromoteBuckets) != 0 {
			return fmt.Errorf("shard nodes require a token of at least 24 bytes and a dedicated configuration")
		}
		return serve(cfg, shardNodeHandler{dir: store.dir, token: cfg.ShardNodeToken})
	}
	if cfg.Cluster != nil && replacement != 0 {
		return fmt.Errorf("start the replacement shard node at its original endpoint and use -heal")
	}
	store.encryption, err = configureEncryption(store.dir, cfg.Encryption)
	if err != nil {
		return err
	}
	cluster, err := configureCluster(store, cfg, !rotateClusterKey)
	if err != nil {
		return err
	}
	if rotateClusterKey {
		return cluster.rotateEncryptionKey(cfg.Encryption.ActiveKey)
	}
	store.erasure, err = configureErasure(store.dir, cfg.Erasure)
	if err != nil {
		return err
	}
	if replacement != 0 {
		if store.erasure == nil {
			return fmt.Errorf("replacement requires an erasure configuration")
		}
		if err := store.erasure.initializeDrive(replacement - 1); err != nil {
			return err
		}
		heal = true
	}
	if heal {
		return store.healAll(cluster == nil)
	}
	if lifecycleOnce {
		return lifecycleCycle(context.Background(), store, cluster)
	}
	replication, err := configureReplication(cfg, store)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replication.start(ctx)
	go runLifecycle(ctx, store, cluster)
	api := &server{store: store, credentials: cfg.Credentials, region: cfg.Region, replication: replication}
	var stats *analytics
	if cfg.Admin != nil {
		stats, err = openAnalytics(store.dir)
		if err != nil {
			return err
		}
		api.admin = &adminConsole{config: *cfg.Admin, analytics: stats}
		go stats.run(ctx)
		go stats.sampleUsage(ctx, store, cluster)
	}
	var handler http.Handler = api
	if cluster != nil {
		handler = cluster.wrap(handler)
	}
	var audit *auditLog
	if cfg.AuditLog {
		audit, err = openAuditLog(store.dir)
		if err != nil {
			return err
		}
		defer audit.close()
	}
	if stats != nil || audit != nil {
		handler = trackRequests(handler, stats, audit)
	}
	return serve(cfg, handler)
}

func serve(cfg config, handler http.Handler) error {
	web := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Stash listening on %s", cfg.Listen)
	if cfg.Cert != "" {
		return web.ListenAndServeTLS(cfg.Cert, cfg.Key)
	}
	return web.ListenAndServe()
}
