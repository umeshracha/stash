package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeFinishesRequestsInProgressBeforeStopping(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "done")
	})
	ctx, stop := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- serveListener(ctx, listener, handler, "", "", 5*time.Second) }()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	url := "http://" + listener.Addr().String()
	body := make(chan string, 1)
	go func() {
		resp, err := client.Get(url)
		if err != nil {
			body <- err.Error()
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		body <- string(data)
	}()
	<-started
	stop()

	select {
	case err := <-stopped:
		t.Fatalf("stopped while a request was still running: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// The listener is closed first, so a new client is turned away.
	if resp, err := client.Get(url); err == nil {
		resp.Body.Close()
		t.Fatal("accepted a new request after the stop signal")
	}

	close(release)
	if got := <-body; got != "done" {
		t.Fatalf("the request in progress got %q, want its response", got)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("a normal stop returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop after the last request finished")
	}
}

func TestServeClosesBusyConnectionsAfterTheGracePeriod(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	})
	ctx, stop := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- serveListener(ctx, listener, handler, "", "", 200*time.Millisecond) }()

	go (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Get("http://" + listener.Addr().String())
	<-started
	begin := time.Now()
	stop()
	select {
	case err := <-stopped:
		if err != nil || time.Since(begin) < 150*time.Millisecond {
			t.Fatalf("returned %v after %s, want nil after the grace period", err, time.Since(begin))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request that never finishes kept the server running")
	}
}
