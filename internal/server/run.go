package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
	err = serve(cfg, handler)
	// Requests have finished, so stop the background loops and write the traffic
	// they would otherwise have flushed up to ten seconds from now.
	cancel()
	if stats != nil {
		if flushErr := stats.flush(); flushErr != nil {
			log.Printf("analytics checkpoint: %v", flushErr)
		}
	}
	return err
}

// shutdownGrace is how long requests in progress get to finish after SIGINT or
// SIGTERM. It stays under the 90 seconds systemd waits before it sends SIGKILL.
const shutdownGrace = 30 * time.Second

func serve(cfg config, handler http.Handler) error {
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("Stash listening on %s", cfg.Listen)
	return serveListener(ctx, listener, handler, cfg.Cert, cfg.Key, shutdownGrace)
}

// serveListener serves until ctx ends, then stops accepting connections and gives
// requests in progress up to grace to finish. A normal stop returns nil, so the
// caller's deferred cleanup (storage lock, audit log) runs.
func serveListener(ctx context.Context, listener net.Listener, handler http.Handler, cert, key string, grace time.Duration) error {
	web := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	serving := make(chan error, 1)
	go func() {
		if cert != "" {
			serving <- web.ServeTLS(listener, cert, key)
		} else {
			serving <- web.Serve(listener)
		}
	}()
	select {
	case err := <-serving:
		return err
	case <-ctx.Done():
	}
	log.Printf("Stash is stopping; waiting up to %s for requests in progress", grace)
	finish, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := web.Shutdown(finish); err != nil {
		log.Printf("Stash closed connections that were still busy after %s", grace)
		web.Close()
	}
	<-serving
	return nil
}
