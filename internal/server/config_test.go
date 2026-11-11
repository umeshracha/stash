package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stash.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigRefusesSampleSecrets(t *testing.T) {
	// stash.example.json must never be usable as it stands.
	example, err := os.ReadFile("../../stash.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(writeConfig(t, string(example))); err == nil || !strings.Contains(err.Error(), "sample secret") {
		t.Fatalf("expected the example configuration to be refused, got %v", err)
	}

	const credentials = `"credentials": {"app": {"secret": "%s", "buckets": {"*": "admin"}}}`
	for name, body := range map[string]string{
		"unique secret":  `{` + strings.Replace(credentials, "%s", "k3Jf92hdP0qLx7vN", 1) + `}`,
		"unique console": `{` + strings.Replace(credentials, "%s", "k3Jf92hdP0qLx7vN", 1) + `, "admin": {"username": "ops", "password": "Zx81mQ4vB7nTc2Ld"}}`,
	} {
		if _, err := loadConfig(writeConfig(t, body)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, body := range map[string]string{
		"upper-case sample": `{` + strings.Replace(credentials, "%s", "REPLACE-THIS-secret-1234", 1) + `}`,
		"sample console":    `{` + strings.Replace(credentials, "%s", "k3Jf92hdP0qLx7vN", 1) + `, "admin": {"username": "ops", "password": "replace-this-console-password"}}`,
	} {
		if _, err := loadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "sample") {
			t.Errorf("%s: expected a sample-secret error, got %v", name, err)
		}
	}
}
