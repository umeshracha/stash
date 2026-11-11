package server

import (
	"errors"
	"io"
	"net/http"
	"time"
)

// limitIdle returns the request with a body that fails with os.ErrDeadlineExceeded
// when it delivers nothing for about timeout, so a stalled client cannot hold a
// handler, a file and any lock the handler took for as long as it likes. A client
// that is sending, however slowly, is never cut off.
//
// The deadline is moved forward at most once in a quarter of the timeout, so a
// stalled body ends between 75% and 100% of the timeout after its last byte. It
// is cleared when the body reaches its end, so it cannot fire while the handler
// works on the response. When the body fails or is left unread the deadline is
// left in place, because net/http then tries to read the rest of it before it
// replies, and that read must not wait for a client that has stopped sending.
//
// The handler gets a copy of the request. net/http looks at the type of the
// server's own r.Body to decide what to do with an unread body after the reply,
// and a wrapper there makes it wait for the rest from a stalled client.
func limitIdle(w http.ResponseWriter, r *http.Request, timeout time.Duration) *http.Request {
	if timeout <= 0 || r.Body == nil || r.Body == http.NoBody {
		return r
	}
	guarded := r.WithContext(r.Context())
	guarded.Body = &idleBody{ReadCloser: r.Body, set: http.NewResponseController(w).SetReadDeadline, timeout: timeout}
	return guarded
}

type idleBody struct {
	io.ReadCloser
	set     func(time.Time) error
	timeout time.Duration
	armed   time.Time
	done    bool // the body ended, or the connection cannot take a read deadline
}

func (b *idleBody) Read(p []byte) (int, error) {
	if !b.done && time.Since(b.armed) > b.timeout/4 {
		if err := b.set(time.Now().Add(b.timeout)); err != nil {
			// HTTP/1 and HTTP/2 connections accept a deadline; a test recorder does not.
			b.done = errors.Is(err, http.ErrNotSupported)
		} else {
			b.armed = time.Now()
		}
	}
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && !b.done {
		b.done = true
		b.set(time.Time{})
	}
	return n, err
}
