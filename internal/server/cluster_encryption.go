package server

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"stash/internal/encryption"
	"stash/internal/etcd"
)

func clusterActiveKey(local, authoritative []byte) (string, error) {
	if len(local) == 0 && len(authoritative) == 0 {
		return "", nil
	}
	configured, err := encryption.DecodeBinding(local)
	if err != nil {
		return "", err
	}
	required, err := encryption.DecodeBinding(authoritative)
	if err != nil {
		return "", err
	}
	if !configured.Includes(required) {
		return "", errors.New("cluster coordinator is missing a required encryption key or fingerprint")
	}
	return required.Active, nil
}

func (cluster *metadataCluster) rotateEncryptionKey(active string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	encoded, revision, err := cluster.read(ctx)
	if err != nil {
		return err
	}
	var root clusterRoot
	if json.Unmarshal(encoded, &root) != nil || root.Format != "bucket-partitions-v1" || root.Generation != cluster.generation || len(root.Encryption) == 0 {
		return errors.New("key rotation requires an existing encrypted cluster")
	}
	required, err := encryption.DecodeBinding(root.Encryption)
	if err != nil {
		return err
	}
	local, err := clusterEncryptionBinding(cluster.store.dir)
	if err != nil {
		return err
	}
	configured, err := encryption.DecodeBinding(local)
	if err != nil {
		return err
	}
	if !configured.Includes(required) || configured.Keys[active] == "" {
		return errors.New("rotation requires the new key and all previously committed keys")
	}
	if active == required.Active {
		return nil
	}
	required.Keys[active] = configured.Keys[active]
	required.Active = active
	root.Encryption, err = json.Marshal(required)
	if err != nil {
		return err
	}
	next, err := json.Marshal(root)
	if err != nil {
		return err
	}
	committed, err := cluster.commit(ctx, revision, next)
	if err != nil {
		return err
	}
	if committed == "" {
		return etcd.ErrQuorum
	}
	return nil
}
