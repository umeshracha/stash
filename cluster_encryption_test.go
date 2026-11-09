package main

import (
	"encoding/json"
	"testing"
)

func TestClusterKeyRotationRequiresAuthoritativeKeyring(t *testing.T) {
	bind := func(active string, keys map[string]string) []byte {
		t.Helper()
		data, err := json.Marshal(keyBinding{encryptionVersion, active, keys})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	old := digest("old")
	next := digest("next")
	oldOnly := bind("old", map[string]string{"old": old})
	preloaded := bind("old", map[string]string{"old": old, "next": next})
	rotated := bind("next", map[string]string{"old": old, "next": next})
	wrong := bind("old", map[string]string{"old": old, "next": digest("different")})

	for _, test := range []struct {
		name        string
		local, root []byte
		active      string
		reject      bool
	}{
		{"plaintext", nil, nil, "", false},
		{"uncommitted key", rotated, oldOnly, "old", false},
		{"rotation visible", preloaded, rotated, "next", false},
		{"stale keyring", oldOnly, rotated, "", true},
		{"different key bytes", wrong, rotated, "", true},
		{"missing encryption", nil, rotated, "", true},
		{"plaintext cluster", rotated, nil, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			active, err := clusterActiveKey(test.local, test.root)
			if (err != nil) != test.reject || active != test.active {
				t.Fatalf("active key %q, error %v", active, err)
			}
		})
	}
}
