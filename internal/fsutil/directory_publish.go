package fsutil

import (
	"os"
	"path/filepath"
	"sync"
)

// DirectoryPublisher batches publication in the same directory. Every successful
// rename is followed by a directory sync before its caller can return.
type DirectoryPublisher struct {
	mu      sync.Mutex
	pending map[string]*directoryBatch
}

type directoryBatch struct {
	start    chan struct{}
	done     chan struct{}
	requests []*directoryRequest
	err      error
}

type directoryRequest struct {
	file        *os.File
	destination string
	err         error
}

func (s *DirectoryPublisher) Publish(file *os.File, destination string, smallObject bool) error {
	path := filepath.Dir(destination)
	if !smallObject || filepath.Dir(file.Name()) != path || !canBatchObjectFile(file) {
		if err := file.Sync(); err != nil {
			return err
		}
		if err := renameObject(file, destination); err != nil {
			return err
		}
		return SyncDir(path)
	}
	request := &directoryRequest{file: file, destination: destination}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[string]*directoryBatch)
	}
	next, running := s.pending[path]
	if next != nil {
		next.requests = append(next.requests, request)
		s.mu.Unlock()
		<-next.done
		return next.result(request)
	}
	batch := &directoryBatch{
		start: make(chan struct{}), done: make(chan struct{}),
		requests: []*directoryRequest{request},
	}
	if running {
		s.pending[path] = batch
		s.mu.Unlock()
		<-batch.start
	} else {
		s.pending[path] = nil
		s.mu.Unlock()
	}

	syncObjectFiles(batch.requests)
	published := false
	for _, item := range batch.requests {
		if item.err == nil {
			item.err = renameObject(item.file, item.destination)
		}
		published = published || item.err == nil
	}
	if published {
		batch.err = SyncDir(path)
	}

	s.mu.Lock()
	if next := s.pending[path]; next != nil {
		s.pending[path] = nil
		close(next.start)
	} else {
		delete(s.pending, path)
	}
	close(batch.done)
	s.mu.Unlock()
	return batch.result(request)
}

func (batch *directoryBatch) result(request *directoryRequest) error {
	if request.err != nil {
		return request.err
	}
	return batch.err
}

func renameObject(file *os.File, destination string) error {
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}
