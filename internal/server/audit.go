package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const auditFile = ".audit.jsonl"
const auditMaxBytes = 10 << 20
const auditArchives = 4

type auditLog struct {
	mu        sync.Mutex
	dir       string
	file      *os.File
	size      int64
	lastError time.Time
}

type auditEvent struct {
	Time       time.Time `json:"time"`
	RequestID  string    `json:"request_id"`
	Credential string    `json:"credential,omitempty"`
	Bucket     string    `json:"bucket,omitempty"`
	Operation  string    `json:"operation"`
	Status     int       `json:"status"`
	DurationMS int64     `json:"duration_ms"`
}

func openAuditLog(dir string) (*auditLog, error) {
	a := &auditLog{dir: dir}
	if err := a.open(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *auditLog) open() error {
	file, err := os.OpenFile(filepath.Join(a.dir, auditFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	a.file, a.size = file, info.Size()
	return nil
}

func (a *auditLog) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		a.file.Close()
		a.file = nil
	}
}

func (a *auditLog) rotate() error {
	if err := a.file.Close(); err != nil {
		a.file = nil
		return err
	}
	a.file = nil
	for i := auditArchives; i > 0; i-- {
		from := auditFile
		if i > 1 {
			from = fmt.Sprintf("%s.%d", auditFile, i-1)
		}
		to := fmt.Sprintf("%s.%d", auditFile, i)
		if err := os.Rename(filepath.Join(a.dir, from), filepath.Join(a.dir, to)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := a.open(); err != nil {
		return err
	}
	return syncDir(a.dir)
}

func (a *auditLog) record(event auditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.append(event); err != nil && time.Since(a.lastError) >= time.Minute {
		log.Printf("audit log: %v", err)
		a.lastError = time.Now()
	}
}

func (a *auditLog) append(event auditEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if a.file == nil {
		if err := a.open(); err != nil {
			return err
		}
	}
	if a.size+int64(len(body)) > auditMaxBytes {
		if err := a.rotate(); err != nil {
			return err
		}
	}
	n, err := a.file.Write(body)
	a.size += int64(n)
	if err != nil {
		return err
	}
	return a.file.Sync()
}
