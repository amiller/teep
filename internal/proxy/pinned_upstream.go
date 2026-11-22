package proxy

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

const maxPinnedUpstreamPools = 1000

func newUpstreamTransport() *http.Transport {
	return tlsct.NewPooledTransport()
}

type pinnedUpstreamKey struct {
	provider  string
	authority string
}

type pinnedUpstreamEntry struct {
	identity  tlsct.TransportIdentity
	client    *http.Client
	transport *http.Transport
	lastUsed  time.Time
}

type pinnedUpstreamPools struct {
	mu      sync.Mutex
	entries map[pinnedUpstreamKey]*pinnedUpstreamEntry
}

func newPinnedUpstreamPools() *pinnedUpstreamPools {
	return &pinnedUpstreamPools{entries: make(map[pinnedUpstreamKey]*pinnedUpstreamEntry)}
}

// pinnedClientForIdentity selects a pool scoped to the provider and attested
// identity. Replacing a pool closes its idle connections; acquired attempts
// may finish on the previous pool within their caller deadlines.
func (s *Server) pinnedClientForIdentity(providerName string, identity tlsct.TransportIdentity) (*http.Client, error) {
	if s.pinnedUpstreams == nil || s.cfg == nil {
		return nil, errors.New("pinned upstream pools are not initialized")
	}
	if identity.Authority() == "" {
		return nil, errors.New("missing attested transport identity")
	}
	key := pinnedUpstreamKey{provider: providerName, authority: identity.Authority()}

	s.pinnedUpstreams.mu.Lock()
	if entry := s.pinnedUpstreams.entries[key]; entry != nil &&
		entry.identity.Equal(identity) {
		entry.lastUsed = time.Now()
		client := entry.client
		s.pinnedUpstreams.mu.Unlock()
		return client, nil
	}

	base := newUpstreamTransport()
	client, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(0, base, identity, !s.cfg.Offline)
	if err != nil {
		s.pinnedUpstreams.mu.Unlock()
		return nil, err
	}
	entry := &pinnedUpstreamEntry{identity: identity, client: client, transport: base, lastUsed: time.Now()}
	client.Transport = tlsct.WrapCounting(
		tlsct.WrapLogging(tlsct.WrapAbandon(client.Transport, func() { s.pinnedUpstreams.retire(key, entry) })),
		func() { s.stats.httpRequests.Add(1) },
		func() { s.stats.httpErrors.Add(1) },
	)

	old := s.pinnedUpstreams.entries[key]
	s.pinnedUpstreams.entries[key] = entry
	evicted := s.pinnedUpstreams.evictOldestLocked(key)
	s.pinnedUpstreams.mu.Unlock()

	if old != nil {
		old.transport.CloseIdleConnections()
	}
	if evicted != nil {
		evicted.transport.CloseIdleConnections()
	}
	return client, nil
}

// retire removes entry so that the next request for key dials a new pool:
// after an abandoned request, its connection may be wedged. Streams in flight
// on entry finish. Its idle connections close now, the rest at IdleConnTimeout
// or the HTTP/2 health check.
func (p *pinnedUpstreamPools) retire(key pinnedUpstreamKey, entry *pinnedUpstreamEntry) {
	p.mu.Lock()
	if p.entries[key] == entry {
		delete(p.entries, key)
	}
	p.mu.Unlock()
	entry.transport.CloseIdleConnections()
}

func (p *pinnedUpstreamPools) evictOldestLocked(exclude pinnedUpstreamKey) *pinnedUpstreamEntry {
	if len(p.entries) <= maxPinnedUpstreamPools {
		return nil
	}
	var oldestKey pinnedUpstreamKey
	var oldest *pinnedUpstreamEntry
	for key, entry := range p.entries {
		if key == exclude {
			continue
		}
		if oldest == nil || entry.lastUsed.Before(oldest.lastUsed) {
			oldestKey = key
			oldest = entry
		}
	}
	if oldest != nil {
		delete(p.entries, oldestKey)
	}
	return oldest
}
