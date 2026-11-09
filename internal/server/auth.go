package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"stash/internal/sigv4"
)

type credential struct {
	PolicyNames []string `json:"policies"`
	rules       []policyStatement
	id          string
	Label       string            `json:"label"`
	Secret      string            `json:"secret"`
	Buckets     map[string]string `json:"buckets"`
}

func digest(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func (s *server) authorize(r *http.Request) (credential, bool) {
	id, ok := sigv4.Verify(r, s.region, func(id string) (string, bool) {
		c, exists := s.credentials[id]
		return c.Secret, exists
	})
	if !ok {
		return credential{}, false
	}
	c := s.credentials[id]
	c.id = id
	return c, true
}
