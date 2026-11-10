package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDirectoryPublisherKeepsConcurrentFailuresSeparate(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	const writes = 16
	var publisher DirectoryPublisher
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := range writes {
		group.Go(func() {
			payload := fmt.Sprintf("object %d", i)
			file, err := os.CreateTemp(dir, ".upload-")
			if err != nil {
				t.Error(err)
				return
			}
			defer os.Remove(file.Name())
			defer file.Close()
			if _, err := file.WriteString(payload); err != nil {
				t.Error(err)
				return
			}
			<-start
			if i == 0 {
				if err := publisher.Publish(file, blocked, true); err == nil {
					t.Error("publishing over a directory succeeded")
				}
				return
			}
			destination := filepath.Join(dir, payload)
			if err := publisher.Publish(file, destination, true); err != nil {
				t.Error(err)
				return
			}
			got, err := os.ReadFile(destination)
			if err != nil || string(got) != payload {
				t.Errorf("published %q, want %q: %v", got, payload, err)
			}
		})
	}
	close(start)
	group.Wait()
}
