package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// A request cancelled mid-stream retires its pinned pool: the next request
// opens a new connection, and a stream that shares the old connection
// finishes (souk-co/souk#1146).
func TestAbandonedStreamRetiresPinnedPool(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		release := make(chan struct{})
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			switch r.URL.Path {
			case "/stall":
				<-r.Context().Done()
			case "/sibling":
				<-release
				_, _ = io.WriteString(w, "data: last\n\n")
			}
		}))
		server := newTLSBindingTestServerHandle()
		server.cfg.Offline = true
		defer server.Close()
		authorityName, err := tlsct.HTTPSOriginAuthority(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := tlsct.NewTransportIdentity(authorityName, fp)
		if err != nil {
			t.Fatal(err)
		}
		send := func(ctx context.Context, path string) (resp *http.Response, local string) {
			t.Helper()
			client, err := server.pinnedClientForIdentity("nearcloud", identity)
			if err != nil {
				t.Fatal(err)
			}
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { local = info.Conn.LocalAddr().String() }})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.ProtoMajor != 2 {
				t.Fatalf("protocol = %s, want HTTP/2", resp.Proto)
			}
			if _, err := io.ReadFull(resp.Body, make([]byte, len("data: first\n\n"))); err != nil {
				t.Fatal(err)
			}
			return resp, local
		}

		sibling, siblingConn := send(context.Background(), "/sibling")
		defer sibling.Body.Close()
		ctx, cancel := context.WithCancel(context.Background())
		stalled, stalledConn := send(ctx, "/stall")
		if stalledConn != siblingConn {
			t.Fatalf("streams did not share a connection: %s, %s", siblingConn, stalledConn)
		}
		cancel()
		stalled.Body.Close()

		fresh, freshConn := send(context.Background(), "/fresh")
		if _, err := io.ReadAll(fresh.Body); err != nil {
			t.Fatal(err)
		}
		fresh.Body.Close()
		t.Logf("connection before cancel %s, after cancel %s", stalledConn, freshConn)
		if freshConn == stalledConn {
			t.Fatal("request after a cancelled stream reused its connection")
		}

		close(release)
		rest, err := io.ReadAll(sibling.Body)
		if err != nil || !strings.Contains(string(rest), "last") {
			t.Fatalf("stream sharing the abandoned connection did not finish: %q, %v", rest, err)
		}

		again, againConn := send(context.Background(), "/again")
		_, _ = io.ReadAll(again.Body)
		again.Body.Close()
		if againConn != freshConn {
			t.Fatalf("a completed response retired its pool: %s, then %s", freshConn, againConn)
		}
	})
}
