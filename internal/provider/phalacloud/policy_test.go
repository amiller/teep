package phalacloud

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// The policy recognizes every image of the model CVM composes in the
// session fixtures as a model component. dstack-ingress runs in both tiers.
func TestSupplyChainPolicyModelCVM(t *testing.T) {
	policy := SupplyChainPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ file, id string }{
		{"session_phala_direct_0_6_3.json", phalaDirect063SessionID},
		{"session_phala_direct.json", phalaDirectSessionID},
	} {
		s := loadSession(t, fixture.file, fixture.id)
		ev, err := sessionEvidenceOf(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		repos := attestation.ExtractComposeDigests(ev.raw.AppCompose).Repos
		if len(repos) != 6 {
			t.Errorf("%s: compose images %v, want 6", fixture.file, repos)
		}
		for _, repo := range repos {
			if !policy.AllowedInModel(repo) {
				t.Errorf("%s: %s not allowed in the model tier", fixture.file, repo)
			}
		}
	}
	if !policy.AllowedInGateway("ghcr.io/dstack-tee/dstack-ingress") {
		t.Error("dstack-ingress not allowed in the gateway tier")
	}
}
