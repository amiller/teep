package tlsct

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// freezeProxy forwards TCP to an upstream. Once frozen it drops every byte in
// both directions and keeps both sockets open: the client sees a connection
// that neither answers nor closes, and the upstream never sees its PINGs.
type freezeProxy struct {
	addr         string
	frozen       atomic.Bool
	clientClosed chan struct{}
}

func newFreezeProxy(t *testing.T, upstream string) *freezeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &freezeProxy{addr: ln.Addr().String(), clientClosed: make(chan struct{})}
	go func() {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		server, err := net.Dial("tcp", upstream)
		if err != nil {
			client.Close()
			return
		}
		t.Cleanup(func() { client.Close(); server.Close() })
		go p.pipe(server, client)
		p.pipe(client, server)
		close(p.clientClosed)
	}()
	return p
}

func (p *freezeProxy) pipe(src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if !p.frozen.Load() {
			_, _ = dst.Write(buf[:n])
		}
	}
}

// After the upstream has sent the response headers and a first chunk, every
// frame stops. Without a health check the read waits for the request
// deadline; with the pooled transport's health check the connection closes
// within SendPingTimeout+PingTimeout (souk-co/souk#1146).
func TestPooledTransportHTTP2HealthCheckClosesWedgedConnection(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		const first = "data: first\n\n"
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, first)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		for _, tc := range []struct {
			name        string
			healthCheck bool
		}{{"health_check", true}, {"without_health_check", false}} {
			t.Run(tc.name, func(t *testing.T) {
				base := NewPooledTransport()
				if base.HTTP2 == nil || base.HTTP2.SendPingTimeout == 0 || base.HTTP2.PingTimeout == 0 {
					t.Fatal("pooled transport has no HTTP/2 health check")
				}
				const idle, ping = 300 * time.Millisecond, 300 * time.Millisecond
				base.HTTP2.SendPingTimeout, base.HTTP2.PingTimeout = idle, ping
				if !tc.healthCheck {
					base.HTTP2.SendPingTimeout = 0
				}
				defer base.CloseIdleConnections()
				proxy := newFreezeProxy(t, ts.Listener.Addr().String())
				origin := "https://" + proxy.addr
				client, err := NewSPKIPinnedHTTPClientWithTransport(0, base, pinnedTestIdentity(t, origin, certificateSPKI(t, ts)), false)
				if err != nil {
					t.Fatal(err)
				}
				deadline := 3 * time.Second
				ctx, cancel := context.WithTimeout(context.Background(), deadline)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.ProtoMajor != 2 {
					t.Fatalf("protocol = %s, want HTTP/2", resp.Proto)
				}
				if _, err := io.ReadFull(resp.Body, make([]byte, len(first))); err != nil {
					t.Fatal(err)
				}
				proxy.frozen.Store(true)
				started := time.Now()
				_, err = io.ReadAll(resp.Body)
				elapsed := time.Since(started)
				t.Logf("read ended after %v: %v", elapsed.Round(time.Millisecond), err)
				if err == nil {
					t.Fatal("read of a wedged stream succeeded")
				}
				if !tc.healthCheck {
					if ctx.Err() == nil {
						t.Fatalf("read without a health check ended before the request deadline: %v", err)
					}
					return
				}
				if ctx.Err() != nil || elapsed > idle+ping+time.Second {
					t.Fatalf("health check did not close the connection within %v (took %v)", idle+ping, elapsed)
				}
				select {
				case <-proxy.clientClosed:
				case <-time.After(time.Second):
					t.Fatal("client did not close the wedged connection")
				}
			})
		}
	})
}
