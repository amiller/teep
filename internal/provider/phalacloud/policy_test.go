package phalacloud

import (
	"context"
	"slices"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// The policy recognizes every image of the model CVM compose in the
// session fixture as a model component. dstack-ingress runs in both tiers.
func TestSupplyChainPolicyModelCVM(t *testing.T) {
	policy := SupplyChainPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	s := loadSession(t, "session_phala_direct_0_6_3.json", phalaDirect063SessionID)
	ev, err := sessionEvidenceOf(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	repos := attestation.ExtractComposeDigests(ev.raw.AppCompose).Repos
	if !slices.Equal(repos, modelCVMImages) {
		t.Fatalf("compose images %v, want %v", repos, modelCVMImages)
	}
	for _, repo := range repos {
		if !policy.AllowedInModel(repo) {
			t.Errorf("%s not allowed in the model tier", repo)
		}
	}
	if !policy.AllowedInGateway("ghcr.io/dstack-tee/dstack-ingress") {
		t.Error("dstack-ingress not allowed in the gateway tier")
	}
}
