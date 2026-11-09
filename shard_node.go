package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const shardRoute = "/.stash/shards/"
const maxShardFile = maxMultipartSize + maxMultipartSize/1024 + shardRecordSize

type shardNode struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

type shardNodeHandler struct {
	dir   string
	token string
}

func shardTokenMatches(r *http.Request, token string) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return (r.TLS != nil || loopback(host)) &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
}

func (h shardNodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := strings.CutPrefix(r.URL.Path, shardRoute)
	namespace, id, found := strings.Cut(route, "/")
	if !ok || !shardID(namespace) || found && !shardID(id) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if !shardTokenMatches(r, h.token) {
		http.Error(w, "access denied", 403)
		return
	}
	dir := filepath.Join(h.dir, namespace)
	if !found {
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "shard inventory unavailable", 503)
			return
		}
		ids := make([]string, 0, len(entries))
		for _, entry := range entries {
			id, ok := strings.CutSuffix(entry.Name(), ".shard")
			if ok && shardID(id) && entry.Type().IsRegular() {
				ids = append(ids, id)
			}
		}
		if len(ids) > maxManifest/36 {
			http.Error(w, "shard inventory too large", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ids)
		return
	}
	path := filepath.Join(dir, id+".shard")
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		file, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, id, time.Time{}, file)
	case http.MethodPut:
		if r.ContentLength < 0 || r.ContentLength > maxShardFile || r.ContentLength%shardRecordSize != 0 {
			http.Error(w, "invalid shard length", 400)
			return
		}
		if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			http.Error(w, "cannot initialize shard storage", 503)
			return
		}
		file, err := os.CreateTemp(dir, ".stash-shard-")
		if err != nil {
			http.Error(w, "shard storage unavailable", 503)
			return
		}
		defer os.Remove(file.Name())
		defer file.Close()
		count, err := io.Copy(file, io.LimitReader(r.Body, r.ContentLength+1))
		if err != nil || count != r.ContentLength {
			http.Error(w, "incomplete shard", 400)
			return
		}
		if err := syncDir(h.dir); err != nil {
			http.Error(w, "shard storage unavailable", 503)
			return
		}
		if err := publishShard(file, path); err != nil {
			http.Error(w, "cannot commit shard", 503)
			return
		}
		w.WriteHeader(201)
	case http.MethodDelete:
		err := os.Remove(path)
		if err == nil {
			err = syncDir(dir)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "cannot delete shard", 503)
			return
		}
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		http.Error(w, "method not allowed", 405)
	}
}

func shardID(value string) bool { return value != "null" && validVersion(value) }

func validateShardNode(node shardNode) (shardNode, error) {
	u, err := url.Parse(node.Endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" && u.Path != "/" || u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) ||
		len(node.Token) < 24 {
		return shardNode{}, errors.New("shard node requires an HTTPS endpoint or loopback HTTP and a token of at least 24 bytes")
	}
	node.Endpoint = strings.TrimRight(node.Endpoint, "/")
	return node, nil
}

type remoteShard struct {
	client          *http.Client
	endpoint, token string
	size            int64
}

func (s *remoteShard) request(method string, body io.Reader, length int64, byteRange string) (*http.Response, error) {
	timeout := 30 * time.Second
	if method == http.MethodPut {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	r, err := http.NewRequestWithContext(ctx, method, s.endpoint, body)
	if err != nil {
		cancel()
		return nil, err
	}
	r.ContentLength = length
	r.Header.Set("Authorization", "Bearer "+s.token)
	if byteRange != "" {
		r.Header.Set("Range", byteRange)
	}
	response, err := s.client.Do(r)
	if err != nil {
		cancel()
		return nil, errShardQuorum
	}
	response.Body = &cancelReadCloser{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func (s *remoteShard) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	end := offset + int64(len(p)) - 1
	if offset >= s.size || end >= s.size {
		return 0, io.EOF
	}
	res, err := s.request(http.MethodGet, nil, 0, fmt.Sprintf("bytes=%d-%d", offset, end))
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPartialContent || res.ContentLength != int64(len(p)) ||
		res.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", offset, end, s.size) {
		return 0, errShardQuorum
	}
	return io.ReadFull(res.Body, p)
}

func (s *remoteShard) Close() error { return nil }
