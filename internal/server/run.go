package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"stash/internal/audit"
	"stash/internal/encryption"
	"stash/internal/erasure"
)

// Options selects an offline maintenance operation when serving is unnecessary.
type Options struct {
	Heal                bool
	ReplaceErasureDrive int
	LifecycleOnce       bool
	RotateClusterKey    bool
}

// Run loads the configuration and starts Stash or performs maintenance.
func Run(path string, options Options) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if options.RotateClusterKey && (cfg.Cluster == nil || cfg.Encryption == nil || options.Heal || options.ReplaceErasureDrive != 0 || options.LifecycleOnce) {
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
		if len(cfg.ShardNodeToken) < 24 || cfg.Erasure != nil || cfg.Encryption != nil || cfg.Cluster != nil || cfg.Admin != nil || cfg.AuditLog || len(cfg.Credentials) != 0 || options.Heal || options.LifecycleOnce || options.ReplaceErasureDrive != 0 ||
			len(cfg.ReplicationExports) != 0 || len(cfg.ReplicaBuckets) != 0 || len(cfg.PromoteBuckets) != 0 {
			return fmt.Errorf("shard nodes require a token of at least 24 bytes and a dedicated configuration")
		}
		return serve(cfg, erasure.NewHandler(store.dir, cfg.ShardNodeToken))
	}
	if cfg.Cluster != nil && options.ReplaceErasureDrive != 0 {
		return fmt.Errorf("start the replacement shard node at its original endpoint and use -heal")
	}
	store.encryption, err = encryption.Open(store.dir, cfg.Encryption)
	if err != nil {
		return err
	}
	cluster, err := configureCluster(store, cfg, !options.RotateClusterKey)
	if err != nil {
		return err
	}
	if options.RotateClusterKey {
		return cluster.rotateEncryptionKey(cfg.Encryption.ActiveKey)
	}
	store.erasure, err = erasure.Open(store.dir, cfg.Erasure)
	if err != nil {
		return err
	}
	if options.ReplaceErasureDrive != 0 {
		if store.erasure == nil {
			return fmt.Errorf("replacement requires an erasure configuration")
		}
		if err := store.erasure.InitializeDrive(options.ReplaceErasureDrive - 1); err != nil {
			return err
		}
		options.Heal = true
	}
	if options.Heal {
		return store.healAll(cluster == nil)
	}
	if options.LifecycleOnce {
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
	var auditLog *audit.Log
	if cfg.AuditLog {
		auditLog, err = audit.Open(store.dir)
		if err != nil {
			return err
		}
		defer auditLog.Close()
	}
	if stats != nil || auditLog != nil {
		handler = trackRequests(handler, stats, auditLog)
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
