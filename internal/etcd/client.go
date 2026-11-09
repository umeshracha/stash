package etcd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const maxResponse = 1536 << 10

var ErrQuorum = errors.New("cluster metadata quorum unavailable")

type Client struct {
	endpoints                         []string
	token, identity, lastReadEndpoint string
	http                              *http.Client
}

func New(endpoints []string, token, caFile, certFile, keyFile, identity string) (*Client, error) {
	config, err := tlsConfig(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return NewWithHTTP(endpoints, token, identity, &http.Client{Transport: &http.Transport{
		TLSClientConfig:     config,
		DialContext:         (&net.Dialer{Timeout: time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout: 60 * time.Second,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}), nil
}

func NewWithHTTP(endpoints []string, token, identity string, client *http.Client) *Client {
	return &Client{endpoints: endpoints, token: token, identity: identity, http: client}
}

func (c *Client) Identity() string { return c.identity }

func (c *Client) Range(ctx context.Context, query any) (RangeResponse, error) {
	var result RangeResponse
	err := c.call(ctx, "/v3/kv/range", query, &result)
	return result, err
}

type RangeResponse struct {
	More   bool `json:"more"`
	Header struct {
		ClusterID string `json:"cluster_id"`
		Revision  string `json:"revision"`
	} `json:"header"`
	KVs []struct {
		Key      string `json:"key"`
		Value    []byte `json:"value"`
		Revision string `json:"mod_revision"`
	} `json:"kvs"`
}

func (c *Client) call(ctx context.Context, path string, value, result any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	endpoints := c.endpoints
	if path == "/v3/kv/txn" {
		endpoints = []string{c.lastReadEndpoint}
	}
	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			break
		}
		callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		request, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint+path, bytes.NewReader(data))
		if err != nil {
			cancel()
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			request.Header.Set("Authorization", c.token)
		}
		response, err := c.http.Do(request)
		if err != nil {
			cancel()
			continue
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			cancel()
			continue
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponse))
		err = decoder.Decode(result)
		response.Body.Close()
		cancel()
		if err == nil {
			if rangeResult, ok := result.(*RangeResponse); ok {
				id := rangeResult.Header.ClusterID
				if id == "" || c.identity != "" && c.identity != id {
					return errors.New("etcd endpoint returned a different cluster identity")
				}
				c.identity = id
				c.lastReadEndpoint = endpoint
			}
			return nil
		}
	}
	return ErrQuorum
}

func (c *Client) Transaction(ctx context.Context, transaction map[string]any) (string, error) {
	var result struct {
		Succeeded bool `json:"succeeded"`
		Header    struct {
			Revision string `json:"revision"`
		} `json:"header"`
	}
	if err := c.call(ctx, "/v3/kv/txn", transaction, &result); err != nil {
		return "", err
	}
	if !result.Succeeded {
		return "", nil
	}
	if n, err := strconv.ParseInt(result.Header.Revision, 10, 64); err != nil || n <= 0 {
		return "", ErrQuorum
	}
	return result.Header.Revision, nil
}

func tlsConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid etcd CA file")
		}
	}
	if certFile != "" || keyFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{pair}
	}
	return config, nil
}
