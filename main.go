package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"
)

type config struct {
	Listen      string                `json:"listen"`
	DataDir     string                `json:"data_dir"`
	Region      string                `json:"region"`
	Cert        string                `json:"tls_cert"`
	Key         string                `json:"tls_key"`
	Credentials map[string]credential `json:"credentials"`
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func main() {
	path := flag.String("config", "stash.json", "path to the JSON configuration")
	flag.Parse()
	if err := run(*path); err != nil {
		log.Fatal(err)
	}
}

func run(path string) error {
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
	if cfg.Listen == "" || cfg.DataDir == "" || cfg.Region == "" || len(cfg.Credentials) == 0 || (cfg.Cert == "") != (cfg.Key == "") {
		return fmt.Errorf("configure listen, data_dir, region, credentials, and both TLS files when enabling TLS")
	}
	for id, c := range cfg.Credentials {
		if id == "" || len(c.Secret) < 16 {
			return fmt.Errorf("each credential needs an ID and a secret of at least 16 bytes")
		}
		for bucket, permission := range c.Buckets {
			if (bucket != "*" && !bucketName.MatchString(bucket)) || (permission != "read" && permission != "write" && permission != "admin") {
				return fmt.Errorf("invalid bucket grant for %q", id)
			}
		}
	}
	store, err := openStore(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.close()
	handler := &server{store: store, credentials: cfg.Credentials, region: cfg.Region}
	web := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Stash listening on %s", cfg.Listen)
	if cfg.Cert != "" {
		return web.ListenAndServeTLS(cfg.Cert, cfg.Key)
	}
	return web.ListenAndServe()
}
