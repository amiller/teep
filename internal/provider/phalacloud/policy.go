package phalacloud

import (
	"slices"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
)

// modelCVMImages are the images of the Phala model CVM, whose compose the
// session audit takes from the session evidence after the compose binding
// passed. The list matches the compose 67ca392a… of the
// deepseek/deepseek-v4.1-flash-1017 model CVM on dstack 0.6.3, observed on
// 2026-11-19 and 2026-11-21; every image is pinned by digest.
var modelCVMImages = []string{
	"ghcr.io/kingsleydon/sglang",
	"ghcr.io/phala-network/phala-inference-guard",
	"ghcr.io/dstack-tee/dstack-ingress",
	"haproxy",
	"grafana/alloy",
	"ghcr.io/phala-network/cvm-log-collector",
}

// SupplyChainPolicy returns the supply chain policy for Phala Cloud. Phala
// Cloud answers with the ACI/1 attestation of the private-ai-gateway, so the
// policy lists the gateway images (SEE: aci.GatewayImages), and the images of
// the model CVM behind its attested sessions (modelCVMImages). An image of
// both tiers has one entry: Lookup returns the first.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	images := aci.GatewayImages()
	for _, repo := range modelCVMImages {
		i := slices.IndexFunc(images, func(img attestation.ImageProvenance) bool { return img.Repo == repo })
		if i >= 0 {
			images[i].ModelTier = true
			continue
		}
		images = append(images, attestation.ImageProvenance{Repo: repo, ModelTier: true, Provenance: attestation.ComposeBindingOnly})
	}
	return &attestation.SupplyChainPolicy{Images: images}
}
