package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// nearComposeManagerFixture holds two instances of one NEAR model from one
// cloud-api.near.ai response: the instance quote and the
// compose_manager_attestation of each, and the client nonce.
type nearComposeManagerFixture struct {
	Nonce     string `json:"nonce"`
	Instances []struct {
		InstanceID     string          `json:"instance_id"`
		IntelQuote     string          `json:"intel_quote"`
		ComposeManager json.RawMessage `json:"compose_manager_attestation"`
	} `json:"instances"`
}

func loadComposeManagerFixture(t *testing.T) (nearComposeManagerFixture, Nonce) {
	t.Helper()
	data, err := os.ReadFile("testdata/near_compose_manager.json")
	if err != nil {
		t.Fatal(err)
	}
	var f nearComposeManagerFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	nonce, err := ParseNonce(f.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	return f, nonce
}

// offlineVerifier checks the certificate chain and signature of a quote
// without Intel PCS collateral.
var offlineVerifier = NewTDXVerifier(true, nil, time.Time{})

// cmReport verifies the compose-manager evidence cm against the instance
// quote and builds the report for policy.
func cmReport(t *testing.T, instanceQuote string, cm []byte, nonce Nonce, policy MeasurementPolicy) (*ComposeManagerResult, map[string]FactorResult) {
	t.Helper()
	raw := &RawAttestation{BackendFormat: FormatNear, ComposeManagerAttestation: cm}
	r := VerifyComposeManager(context.Background(), raw, offlineVerifier(context.Background(), instanceQuote), nonce, offlineVerifier)
	in := &ReportInput{Raw: raw, Policy: policy, ComposeManager: r}
	out := map[string]FactorResult{}
	for _, eval := range []evaluatorFunc{evalComposeManagerQuote, evalComposeManagerTCB, evalComposeManagerActions} {
		f := eval(in)[0]
		out[f.Name] = f
	}
	return r, out
}

// pinnedPolicy allows exactly the files and images that cm's log names.
func pinnedPolicy(t *testing.T, cm []byte) MeasurementPolicy {
	t.Helper()
	_, actions, _, err := parseComposeManager(cm)
	if err != nil {
		t.Fatal(err)
	}
	files, images, err := ComposeManagerDeployments(actions)
	if err != nil {
		t.Fatal(err)
	}
	p := MeasurementPolicy{ComposeManagerComposeAllow: map[string]struct{}{}, ComposeManagerImageAllow: map[string]struct{}{}}
	for _, f := range files {
		p.ComposeManagerComposeAllow[f] = struct{}{}
	}
	for _, img := range images {
		p.ComposeManagerImageAllow[img] = struct{}{}
	}
	return p
}

func wantStatus(t *testing.T, factors map[string]FactorResult, name string, want Status, detail string) {
	t.Helper()
	f := factors[name]
	if f.Status != want {
		t.Fatalf("%s = %v, want %v (%s)", name, f.Status, want, f.Detail)
	}
	if detail != "" && !strings.Contains(f.Detail, detail) {
		t.Fatalf("%s detail %q does not contain %q", name, f.Detail, detail)
	}
}

// editActions applies edit to the decoded compose_manager_attestation and
// re-encodes it.
func editActions(t *testing.T, cm []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(cm, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestComposeManagerCapturedInstancesPass(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	for _, inst := range f.Instances {
		t.Run(inst.InstanceID, func(t *testing.T) {
			r, factors := cmReport(t, inst.IntelQuote, inst.ComposeManager, nonce, pinnedPolicy(t, inst.ComposeManager))
			wantStatus(t, factors, FactorCMQuote, Pass, "REPORTDATA = sha256(")
			wantStatus(t, factors, FactorCMTCB, Skip, "offline")
			wantStatus(t, factors, FactorCMActions, Pass, "running nearaidev/compose-manager@sha256:ae4332fd")
			if len(r.Actions) == 0 {
				t.Fatal("no actions")
			}
		})
	}
}

func TestComposeManagerTamperedActionLog(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	policy := pinnedPolicy(t, inst.ComposeManager)
	cm := editActions(t, inst.ComposeManager, func(m map[string]any) {
		actions := m["actions"].([]any)
		last := actions[len(actions)-1].(map[string]any)
		last["services"] = []any{"exfiltrate"}
	})
	_, factors := cmReport(t, inst.IntelQuote, cm, nonce, policy)
	wantStatus(t, factors, FactorCMQuote, Fail, "is not sha256(actions)")
	wantStatus(t, factors, FactorCMActions, Fail, "not bound")
}

func TestComposeManagerDroppedAction(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	cm := editActions(t, inst.ComposeManager, func(m map[string]any) {
		actions := m["actions"].([]any)
		m["actions"] = actions[1:]
	})
	_, factors := cmReport(t, inst.IntelQuote, cm, nonce, pinnedPolicy(t, inst.ComposeManager))
	wantStatus(t, factors, FactorCMQuote, Fail, "is not sha256(actions)")
}

func TestComposeManagerWrongNonce(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	nonce[0] ^= 1
	_, factors := cmReport(t, inst.IntelQuote, inst.ComposeManager, nonce, pinnedPolicy(t, inst.ComposeManager))
	wantStatus(t, factors, FactorCMQuote, Fail, "|| nonce")
	wantStatus(t, factors, FactorCMActions, Fail, "not bound")
}

// TestComposeManagerOtherInstance gives instance A the genuine, fresh and
// correctly bound compose-manager attestation of instance B, from another
// TD of the same model.
func TestComposeManagerOtherInstance(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	a, b := f.Instances[0], f.Instances[1]
	_, factors := cmReport(t, a.IntelQuote, b.ComposeManager, nonce, pinnedPolicy(t, b.ComposeManager))
	wantStatus(t, factors, FactorCMQuote, Fail, "not from the instance TD")
	wantStatus(t, factors, FactorCMActions, Fail, "not bound")
}

func TestComposeManagerAllowlists(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	const running = "nearaidev/compose-manager@sha256:ae4332fdb0bfccf6410bc153a58d0b72a596a989cbb98fd5b6461fe32e079814"
	const deployed = "0faf0a037c662094be342a5c128fc531bc0145c869e27dc55bab7b1192d605e6"

	t.Run("empty", func(t *testing.T) {
		_, factors := cmReport(t, inst.IntelQuote, inst.ComposeManager, nonce, MeasurementPolicy{})
		wantStatus(t, factors, FactorCMActions, Fail, "compose_manager_compose_allow "+deployed)
		wantStatus(t, factors, FactorCMActions, Fail, "compose_manager_image_allow "+running)
	})
	t.Run("file_missing", func(t *testing.T) {
		p := pinnedPolicy(t, inst.ComposeManager)
		delete(p.ComposeManagerComposeAllow, deployed)
		_, factors := cmReport(t, inst.IntelQuote, inst.ComposeManager, nonce, p)
		wantStatus(t, factors, FactorCMActions, Fail, "not allowed: compose_manager_compose_allow "+deployed)
	})
	t.Run("image_missing", func(t *testing.T) {
		p := pinnedPolicy(t, inst.ComposeManager)
		delete(p.ComposeManagerImageAllow, running)
		_, factors := cmReport(t, inst.IntelQuote, inst.ComposeManager, nonce, p)
		wantStatus(t, factors, FactorCMActions, Fail, "not allowed: compose_manager_image_allow "+running)
	})
}

func TestComposeManagerDeploymentsRules(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	img := "nearaidev/compose-manager@sha256:" + sha
	started := ComposeManagerAction{Action: "compose_manager_started", Image: img}
	for _, tc := range []struct {
		name    string
		actions []ComposeManagerAction
		err     string
	}{
		{"ok", []ComposeManagerAction{{Action: "compose_stage", FileSHA256: sha}, {Action: "compose_up", FileSHA256: sha}, {Action: "compose_down"}, {Action: "docker_restart"}, {Action: "docker_clean"}, {Action: "docker_evict"}, started}, ""},
		{"unknown action", []ComposeManagerAction{{Action: "docker_build"}, started}, "unknown action"},
		{"no start", []ComposeManagerAction{{Action: "compose_up", FileSHA256: sha}}, "no compose_manager_started"},
		{"up without hash", []ComposeManagerAction{{Action: "compose_up"}, started}, "file_sha256"},
		{"uppercase hash", []ComposeManagerAction{{Action: "compose_up", FileSHA256: strings.ToUpper(sha)}, started}, "file_sha256"},
		{"image by tag", []ComposeManagerAction{{Action: "compose_manager_started", Image: "nearaidev/compose-manager:latest"}}, "not pinned by digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ComposeManagerDeployments(tc.actions)
			if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestComposeManagerEvidenceParse(t *testing.T) {
	evidence := func(actions string, extra string) []byte {
		return []byte(fmt.Sprintf(`{"actions":%s,"actions_hash":"","nonce":"","nonce_source":"client","quote":"","event_log":"","report_data":""%s}`, actions, extra))
	}
	var many strings.Builder
	many.WriteByte('[')
	for i := range maxComposeManagerActions + 1 {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`{"timestamp":"t","action":"compose_down"}`)
	}
	many.WriteByte(']')
	for _, tc := range []struct {
		name string
		data []byte
		err  string
	}{
		{"absent", nil, "no compose_manager_attestation"},
		{"ok", evidence(`[{"timestamp":"t","action":"compose_down","services":["a"]}]`, ""), ""},
		{"null actions", evidence(`null`, ""), "actions"},
		{"too many", []byte(evidence(many.String(), "")), "more than"},
		{"null service", evidence(`[{"timestamp":"t","action":"compose_down","services":[null]}]`, ""), "services"},
		{"number service", evidence(`[{"timestamp":"t","action":"compose_down","services":[1]}]`, ""), "services"},
		{"unknown action member", evidence(`[{"timestamp":"t","action":"compose_down","env":"x"}]`, ""), "unknown members"},
		{"unknown member", evidence(`[]`, `,"extra":1`), "unknown members"},
		{"duplicate member", evidence(`[{"timestamp":"t","action":"compose_down","action":"compose_up"}]`, ""), "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseComposeManager(tc.data)
			if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestComposeManagerCanonicalJSON(t *testing.T) {
	got, err := canonicalJSON([]byte(`[ {"b": "<&> é", "a": ["x"]} ]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"a":["x"],"b":"<&> é"}]`; string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

func TestComposeManagerNotApplicableOrMissing(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{BackendFormat: FormatDstack}}
	if got := evalComposeManagerQuote(in)[0].Status; got != NotApplicable {
		t.Fatalf("dstack: %v, want N/A", got)
	}
	raw := &RawAttestation{BackendFormat: FormatNear}
	if r := VerifyComposeManager(context.Background(), &RawAttestation{BackendFormat: FormatDstack}, nil, Nonce{}, offlineVerifier); r != nil {
		t.Fatalf("dstack result = %+v, want nil", r)
	}
	r := VerifyComposeManager(context.Background(), raw, nil, Nonce{}, offlineVerifier)
	in = &ReportInput{Raw: raw, ComposeManager: r}
	for _, eval := range []evaluatorFunc{evalComposeManagerQuote, evalComposeManagerTCB, evalComposeManagerActions} {
		if f := eval(in)[0]; f.Status != Fail || !strings.Contains(f.Detail, "no compose_manager_attestation") {
			t.Fatalf("%s = %v (%s), want Fail", f.Name, f.Status, f.Detail)
		}
	}
	in.ComposeManager = nil
	if f := evalComposeManagerActions(in)[0]; f.Status != Fail {
		t.Fatalf("unverified: %v, want Fail", f.Status)
	}
}
