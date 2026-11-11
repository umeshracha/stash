package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// authorize verifies the request signature. A failure is a *sigv4.Error.
func (s *server) authorize(r *http.Request) (credential, error) {
	id, err := sigv4.Verify(r, s.region, func(id string) (string, bool) {
		c, exists := s.credentials[id]
		return c.Secret, exists
	})
	if err != nil {
		return credential{}, err
	}
	c := s.credentials[id]
	c.id = id
	return c, nil
}

// denyAuth answers a request that failed authentication with the S3 error that says why.
// Naming a wrong access key apart from a wrong secret lets a stranger test which key IDs
// exist; AWS does the same, and the secret stays unguessable. The region header lets an
// SDK that signed for the wrong region retry in the right one.
func (s *server) denyAuth(w http.ResponseWriter, err error) {
	w.Header().Set("X-Amz-Bucket-Region", s.region)
	var failed *sigv4.Error
	if errors.As(err, &failed) {
		failureMessage(w, failed.Status, failed.Code, failed.Message)
		return
	}
	failure(w, 403, "AccessDenied")
}
