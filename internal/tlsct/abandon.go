package tlsct

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
)

// WrapAbandon calls onAbandon when a request ends before its response
// completed: the round trip fails after a connection was assigned, or the
// response body closes before a read returned io.EOF. A cancelled HTTP/2
// stream leaves its connection in the pool, and that connection can be wedged
// (souk-co/souk#1146); onAbandon lets the owner stop using the pool.
func WrapAbandon(base http.RoundTripper, onAbandon func()) http.RoundTripper {
	return &abandonTransport{base: base, onAbandon: onAbandon}
}

type abandonTransport struct {
	base      http.RoundTripper
	onAbandon func()
}

func (t *abandonTransport) CloseIdleConnections() { closeIdleConnections(t.base) }

func (t *abandonTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var assigned atomic.Bool
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { assigned.Store(true) }})
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		if assigned.Load() {
			t.onAbandon()
		}
		return resp, err
	}
	if resp.Body != http.NoBody {
		resp.Body = &abandonBody{ReadCloser: resp.Body, onAbandon: t.onAbandon}
	}
	return resp, nil
}

// abandonBody may be read and closed on different goroutines.
type abandonBody struct {
	io.ReadCloser
	onAbandon func()
	eof       atomic.Bool
	once      sync.Once
}

func (b *abandonBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.eof.Store(true)
	}
	return n, err
}

// Close resets an unfinished stream before onAbandon, so that onAbandon can
// close the connection if it is then idle.
func (b *abandonBody) Close() error {
	err := b.ReadCloser.Close()
	if !b.eof.Load() {
		b.once.Do(b.onAbandon)
	}
	return err
}
