package verify

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// A NearDirect candidate is judged on its evidence alone: the keyless E2EE
// probe, which would fail it as e2ee_usable, runs only on the admitted backend.
func TestCandidateSendsNoE2EEProbe(t *testing.T) {
	opts := &Options{ProviderName: "neardirect", ModelName: "m", candidate: true,
		Provider: &config.Provider{BaseURL: "https://127.0.0.1:1", E2EE: true}}
	raw := &attestation.RawAttestation{SigningKey: "ab"}
	if got := evidenceE2EEOutcome(t.Context(), opts, raw); got != nil {
		t.Fatalf("candidate outcome = %+v, want none", got)
	}
	opts.candidate = false
	if got := evidenceE2EEOutcome(t.Context(), opts, raw); got == nil {
		t.Fatal("admitted outcome = nil, want the keyless probe result")
	}
}
