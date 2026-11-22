package neardirect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearroute"
)

// policyFixture serves /endpoints and a /backends/count of healthy backends.
// Each index's verdict stands in for verifying that backend's attestation:
// true passes policy, false fails it, and an absent index is unreachable.
func policyFixture(t *testing.T, healthy, start uint64, verdicts map[uint64]bool) (r *EndpointResolver, tried func() []uint64) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/endpoints" {
			_, _ = fmt.Fprint(w, `{"endpoints":[{"domain":"model.completions.near.ai","models":["m"]}]}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"domain":"model.completions.near.ai","requested_domain":"model.completions.near.ai","healthy":%d,"total":%d}`, healthy, healthy)
	}))
	t.Cleanup(server.Close)
	r = NewEndpointResolver()
	r.SetClient(server.Client())
	r.endpointsURL, r.countURL = server.URL+"/endpoints", server.URL+"/count"
	r.selector = func(context.Context, uint64) (uint64, error) { return start, nil }
	var mu sync.Mutex
	var calls []uint64
	r.SetAdmission(func(_ context.Context, model string, route provider.ResolvedRoute) (bool, error) {
		var index uint64
		if _, err := fmt.Sscanf(route.Authority(), "model-i%d.completions.near.ai", &index); err != nil || model != "m" {
			return false, fmt.Errorf("unexpected candidate %s for %s", route.Authority(), model)
		}
		mu.Lock()
		calls = append(calls, index)
		mu.Unlock()
		pass, ok := verdicts[index]
		if !ok {
			return false, errors.New("connection refused")
		}
		return !pass, nil
	})
	t.Cleanup(func() { r.Stop(); r.CloseIdleConnections() })
	return r, func() []uint64 { mu.Lock(); defer mu.Unlock(); return slices.Clone(calls) }
}

func TestAdmissionSettlesOnPassingIndex(t *testing.T) {
	for _, tc := range []struct {
		name     string
		start    uint64
		verdicts map[uint64]bool
		want     string
		tried    []uint64
	}{
		{"first passes", 1, map[uint64]bool{0: false, 1: true, 2: false}, "model-i1.completions.near.ai", []uint64{1}},
		{"skips failing", 0, map[uint64]bool{0: false, 1: false, 2: true}, "model-i2.completions.near.ai", []uint64{0, 1, 2}},
		{"wraps", 2, map[uint64]bool{0: true, 1: false, 2: false}, "model-i0.completions.near.ai", []uint64{2, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, tried := policyFixture(t, 3, tc.start, tc.verdicts)
			route, err := r.ResolveRoute(t.Context(), "m")
			if err != nil {
				t.Fatal(err)
			}
			if route.Authority() != tc.want || !slices.Equal(tried(), tc.tried) {
				t.Fatalf("got %s after %v, want %s after %v", route.Authority(), tried(), tc.want, tc.tried)
			}
			if again, err := r.ResolveRoute(t.Context(), "m"); err != nil || again.Authority() != tc.want || len(tried()) != len(tc.tried) {
				t.Fatalf("established route changed or was re-admitted: %s %v %v", again.Authority(), err, tried())
			}
		})
	}
}

func TestAdmissionFailsClosedWhenEveryIndexFails(t *testing.T) {
	r, tried := policyFixture(t, 3, 1, map[uint64]bool{0: false, 1: false, 2: false})
	_, err := r.ResolveRoute(t.Context(), "m")
	var routeErr *nearroute.Error
	if !errors.As(err, &routeErr) || routeErr.Kind != nearroute.Policy {
		t.Fatalf("want policy route error, got %v", err)
	}
	if !slices.Equal(tried(), []uint64{1, 2, 0}) {
		t.Fatalf("tried %v, want each healthy index once", tried())
	}
	if _, ok := r.LookupSelection("m"); ok {
		t.Fatal("failed admission published a selection")
	}
	if _, err := r.ResolveRoute(t.Context(), "m"); err == nil || len(tried()) != 6 {
		t.Fatalf("next resolution did not select again: %v %v", err, tried())
	}
}

func TestAdmissionStopsAtIncompleteVerification(t *testing.T) {
	r, tried := policyFixture(t, 3, 0, map[uint64]bool{1: true, 2: true})
	if _, err := r.ResolveRoute(t.Context(), "m"); err == nil || err.Error() != "connection refused" {
		t.Fatalf("want the verification error, got %v", err)
	}
	if !slices.Equal(tried(), []uint64{0}) {
		t.Fatalf("tried %v after an incomplete verification", tried())
	}
}

func TestRejectReselectsEstablishedRoute(t *testing.T) {
	verdicts := map[uint64]bool{0: true, 1: true}
	r, tried := policyFixture(t, 2, 0, verdicts)
	if route, err := r.ResolveRoute(t.Context(), "m"); err != nil || route.Authority() != "model-i0.completions.near.ai" {
		t.Fatal(route.Authority(), err)
	}
	r.Reject("m", "model-i1.completions.near.ai")
	if _, ok := r.LookupSelection("m"); !ok {
		t.Fatal("rejecting another authority dropped the selection")
	}
	// NEAR now maps index 0 to a backend that fails policy.
	verdicts[0] = false
	r.Reject("m", "model-i0.completions.near.ai")
	route, err := r.ResolveRoute(t.Context(), "m")
	if err != nil || route.Authority() != "model-i1.completions.near.ai" || !slices.Equal(tried(), []uint64{0, 0, 1}) {
		t.Fatalf("got %s %v after %v", route.Authority(), err, tried())
	}
}

func TestRejectKeepsExplicitRoute(t *testing.T) {
	r, tried := policyFixture(t, 2, 0, map[uint64]bool{0: false, 1: false})
	origin := nearroute.Origin{Authority: "model-i0.completions.near.ai", Indexed: true, Index: 0}
	if _, err := r.ResolveConfigured(t.Context(), "m", origin); err != nil {
		t.Fatal(err)
	}
	r.Reject("m", "model-i0.completions.near.ai")
	if _, ok := r.LookupSelection("m"); !ok || len(tried()) != 0 {
		t.Fatal("explicit route was admitted or rejected")
	}
}
