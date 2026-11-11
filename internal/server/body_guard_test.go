package server

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// bodyServer reads each request body to the end, reports how that ended, and
// answers 200, or 400 when the body failed.
func bodyServer(t *testing.T, timeout time.Duration) (addr string, results chan error) {
	t.Helper()
	results = make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = limitIdle(w, r, timeout)
		_, err := io.Copy(io.Discard, r.Body)
		results <- err
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().String(), results
}

func TestIdleBodyEndsAStalledUploadAndAnswersTheClient(t *testing.T) {
	addr, results := bodyServer(t, 200*time.Millisecond)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Promise 100 bytes, send 3, then say nothing.
	conn.Write([]byte("PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc"))

	select {
	case err := <-results:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the body ended with %v, want a deadline error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled body was never ended")
	}

	// net/http reads what is left of an unread body before it replies. That read
	// must not wait for the stalled client, or the answer never comes.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 400") {
		t.Fatalf("the stalled client got %q, %v; want the 400 response", status, err)
	}
}

func TestIdleBodyLetsASlowButSteadyUploadFinish(t *testing.T) {
	addr, results := bodyServer(t, 200*time.Millisecond)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n"))
	// Ten bytes over 800 ms, four times the idle timeout, never idle for 100 ms.
	for i := 0; i < 10; i++ {
		conn.Write([]byte("x"))
		time.Sleep(80 * time.Millisecond)
	}
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("a client that kept sending was cut off: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the upload never finished")
	}
}

func TestIdleBodyIsOffWhenTheTimeoutIsZero(t *testing.T) {
	r := httptest.NewRequest("PUT", "/x", io.NopCloser(io.LimitReader(zeros{}, 5)))
	if limitIdle(httptest.NewRecorder(), r, 0) != r {
		t.Fatal("the request was wrapped although the guard is off")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { return len(p), nil }
