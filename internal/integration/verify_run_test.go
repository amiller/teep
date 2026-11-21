package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/verify"
)

// findResponse returns the body of the first captured response whose URL
// path ends with suffix.
func findResponse(t *testing.T, entries []capture.RecordedEntry, suffix string) []byte {
	t.Helper()
	for i := range entries {
		if u, _, _ := strings.Cut(entries[i].URL, "?"); strings.HasSuffix(u, suffix) {
			return entries[i].Body
		}
	}
	t.Fatalf("no captured response for %s", suffix)
	return nil
}

// buildVerifyRunConfig constructs a minimal config for verify.Run replay tests.
// No API key — the E2EE test will return NoAPIKey and skip live network calls.
func buildVerifyRunConfig(providerName, baseURL string) (*config.Config, *config.Provider) {
	cp := &config.Provider{
		Name:    providerName,
		BaseURL: baseURL,
		APIKey:  "",
	}
	return &config.Config{Providers: map[string]*config.Provider{providerName: cp}}, cp
}

func TestVerifyRun_Venice_Fixture(t *testing.T) {
	env := loadFixture(t, "venice_dstack")
	baseURL := extractBaseURL(t, env.entries)
	t.Logf("base URL: %s", baseURL)

	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:                   cfg,
		Provider:                 cp,
		ProviderName:             env.manifest.Provider,
		ModelName:                env.manifest.Model,
		Offline:                  false,
		Client:                   env.client,
		MetadataClient:           env.client,
		AttestationClientFactory: func() *http.Client { return &http.Client{Transport: env.client.Transport} },
		Nonce:                    env.nonce,
		CapturedE2EE:             fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime:         fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present", "signing_key_present"})

	if report.Passed < 5 {
		t.Errorf("expected at least 5 passing factors, got %d", report.Passed)
	}
}

func TestVerifyRun_NearDirect_Fixture(t *testing.T) {
	env := loadFixture(t, "neardirect_near")

	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, env.manifest.NearConfig.Origin)
	cp.E2EE = env.manifest.NearConfig.E2EE
	// Pin the compose-manager allowlists to the fixture's action log.
	raw, err := neardirect.ParseAttestationResponse(context.Background(), findResponse(t, env.entries, "/v1/attestation/report"), env.manifest.Model)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	offline := attestation.NewTDXVerifier(true, nil, time.Time{})
	var policy attestation.MeasurementPolicy
	pinComposeManager(t, &policy, attestation.VerifyComposeManager(context.Background(), raw, offline(context.Background(), raw.IntelQuote), env.nonce, offline))
	cfg.ProviderPolicies = map[string]attestation.MeasurementPolicy{env.manifest.Provider: policy}
	report, _, err := verify.Replay(context.Background(), findFixtureDir(t, "neardirect_near"), func(string) (*config.Config, *config.Provider, error) { return cfg, cp, nil })

	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present"})
	assertMustPass(t, report, composeManagerFactors)

	if report.Passed < 5 {
		t.Errorf("expected at least 5 passing factors, got %d", report.Passed)
	}
}

func TestVerifyReplay_Venice_Fixture(t *testing.T) {
	fdir := findFixtureDir(t, "venice_dstack")

	_, entries, err := capture.Load(fdir)
	if err != nil {
		t.Fatalf("load capture: %v", err)
	}
	baseURL := extractBaseURL(t, entries)

	cfgLoader := func(providerName string) (*config.Config, *config.Provider, error) {
		cfg, cp := buildVerifyRunConfig(providerName, baseURL)
		return cfg, cp, nil
	}

	report, reportText, err := verify.Replay(context.Background(), fdir, cfgLoader)
	if err != nil {
		t.Fatalf("verify.Replay: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if reportText == "" {
		t.Error("expected non-empty report text")
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present"})
}

func TestVerifyRun_WithCapture_Venice(t *testing.T) {
	env := loadFixture(t, "venice_dstack")
	baseURL := extractBaseURL(t, env.entries)
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	captureDir := t.TempDir()

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:                   cfg,
		Provider:                 cp,
		ProviderName:             env.manifest.Provider,
		ModelName:                env.manifest.Model,
		Offline:                  false,
		Client:                   env.client,
		MetadataClient:           env.client,
		AttestationClientFactory: func() *http.Client { return &http.Client{Transport: env.client.Transport} },
		Nonce:                    env.nonce,
		CaptureDir:               captureDir,
		CapturedE2EE:             fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime:         fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run with capture: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	dirs, readErr := os.ReadDir(captureDir)
	if readErr != nil {
		t.Fatalf("read capture dir: %v", readErr)
	}
	if len(dirs) == 0 {
		t.Error("expected at least one capture subdirectory")
	}
	t.Logf("capture dir: %d subdirectory(ies)", len(dirs))
}

func TestVerifyRun_Tinfoil_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_cloud_tinfoil")
	baseURL := extractBaseURL(t, env.entries)
	t.Logf("base URL: %s", baseURL)

	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:                   cfg,
		Provider:                 cp,
		ProviderName:             env.manifest.Provider,
		ModelName:                env.manifest.Model,
		Offline:                  false,
		Client:                   env.client,
		MetadataClient:           env.client,
		AttestationClientFactory: func() *http.Client { return &http.Client{Transport: env.client.Transport} },
		Nonce:                    env.nonce,
		CapturedE2EE:             fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime:         fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	// The cloud fixture attests the Tinfoil router, which is a gateway and not
	// the endpoint that runs the model, so the SEV-SNP evidence is asserted on
	// the gateway factors. The core factors describe a backend that Tinfoil
	// exposes no evidence about, and they fail by default.
	// SEE: docs/attestation_gaps/tinfoil_cloud_integrity.md
	assertMustPass(t, report, []string{
		"nonce_match",
		"gateway_nonce_match",
		"gateway_tee_quote_present",
		"gateway_tee_quote_structure",
		"gateway_tee_cert_chain",
		"gateway_tee_quote_signature",
		"gateway_tee_debug_disabled",
		"gateway_tee_reportdata_binding",
		"gateway_tee_hardware_config",
		"gateway_tee_measurement",
		"signing_key_present",
		"e2ee_capable",
		"tls_key_binding",
	})

	if report.Passed < 13 {
		t.Errorf("expected at least 13 passing factors, got %d", report.Passed)
	}
}

func TestVerifyRun_TinfoilDirect_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_direct_tinfoil")

	// Direct mode uses the proxy discovery endpoint on inference.tinfoil.sh
	// to resolve model → backend enclave domain, then fetches attestation
	// from the resolved enclave. The capture is of inf16-0, selected with
	// enclaves.
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, "https://inference.tinfoil.sh")
	cp.Enclaves = []string{"deepseek-v4-1-flash-inf16-0.tinfoil.containers.tinfoil.dev"}

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:                   cfg,
		Provider:                 cp,
		ProviderName:             env.manifest.Provider,
		ModelName:                env.manifest.Model,
		Offline:                  false,
		Client:                   env.client,
		MetadataClient:           env.client,
		AttestationClientFactory: func() *http.Client { return &http.Client{Transport: env.client.Transport} },
		Nonce:                    env.nonce,
		CapturedE2EE:             fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime:         fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	// Tinfoil direct fixture is TDX with Intel PCS collateral, NVIDIA GPU
	// evidence, and Tinfoil Sigstore supply-chain evidence captured.
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_measurement",
		"tee_boot_config",
		"tee_reportdata_binding",
		"tee_tcb_current",
		"tee_tcb_not_revoked",
		"signing_key_present",
		"e2ee_capable",
		"e2ee_usable",
		"tls_key_binding",
		"nvidia_payload_present",
		"nvidia_signature",
		"nvidia_claims",
		"cpu_gpu_chain",
		"measured_model_weights",
		"build_transparency_log",
		"component_recognition",
		"provider_signer_recognition",
		"component_signature_recognition",
		"sigstore_code_verified",
	})

	if report.Passed < 24 {
		t.Errorf("expected at least 24 passing factors, got %d", report.Passed)
	}
}
