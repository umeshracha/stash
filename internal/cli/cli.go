package cli

import (
	"flag"
	"log"

	"stash/internal/server"
)

// Main runs the Stash command with the process arguments.
func Main() {
	path := flag.String("config", "stash.json", "path to the JSON configuration")
	heal := flag.Bool("heal", false, "verify and repair erasure shards while the server is stopped")
	replacement := flag.Int("replace-erasure-drive", 0, "initialize replacement drive by its one-based index and heal while offline")
	lifecycleOnce := flag.Bool("lifecycle-once", false, "run one lifecycle expiration sweep and exit")
	rotateClusterKey := flag.Bool("rotate-cluster-key", false, "activate the configured encryption key through the cluster metadata quorum and exit")
	flag.Parse()
	if err := server.Run(*path, server.Options{
		Heal:                *heal,
		ReplaceErasureDrive: *replacement,
		LifecycleOnce:       *lifecycleOnce,
		RotateClusterKey:    *rotateClusterKey,
	}); err != nil {
		log.Fatal(err)
	}
}
