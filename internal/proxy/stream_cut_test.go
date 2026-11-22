package proxy_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// An upstream stream that the network cuts before [DONE] reaches the client
// as an upstream_error event with no [DONE]; a complete stream is unchanged.
func TestStreamUpstreamCutReachesClient(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, cut := range []bool{false, true} {
			t.Run(fmt.Sprintf("cut=%v", cut), func(t *testing.T) {
				upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					sse := streamSSE("partial")
					_, _ = io.WriteString(w, strings.TrimSuffix(sse, "data: [DONE]\n\n"))
					w.(http.Flusher).Flush()
					if cut {
						panic(http.ErrAbortHandler)
					}
					_, _ = io.WriteString(w, "data: [DONE]\n\n")
				})
				proxySrv := newNeardirectProxyServer(t, authority, upstream)
				defer proxySrv.Close()
				resp, err := postChat(t, proxySrv.URL, "neardirect:test-model", true)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				raw, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("read client stream: %v", err)
				}
				body := string(raw)
				if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"content":"partial"`) {
					t.Fatalf("status=%d body=%s", resp.StatusCode, body)
				}
				hasError := strings.Contains(body, "event: error\ndata: {\"error\":{\"message\":\"upstream stream ended early: ")
				hasUpstreamType := strings.Contains(body, `"type":"upstream_error"`)
				hasDone := strings.Contains(body, "data: [DONE]")
				if cut != hasError || cut != hasUpstreamType || cut == hasDone {
					t.Fatalf("cut=%v error_event=%v done=%v\n%s", cut, hasError, hasDone, body)
				}
			})
		}
	})
}
