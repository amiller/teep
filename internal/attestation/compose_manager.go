package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// maxComposeManagerActions bounds the action log of one compose-manager
// attestation.
const maxComposeManagerActions = 10_000

// ComposeManagerAction is one entry of the compose-manager action log, with
// the members that nearai/compose-manager defines (DeploymentAction).
type ComposeManagerAction struct {
	Timestamp  string    `json:"timestamp"`
	Action     string    `json:"action"`
	Tag        string    `json:"tag,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	File       string    `json:"file,omitempty"`
	FileSHA256 string    `json:"file_sha256,omitempty"`
	Services   []*string `json:"services,omitempty"`
	Container  string    `json:"container,omitempty"`
	Image      string    `json:"image,omitempty"`
}

// composeManagerEvidence is the compose_manager_attestation member of a NEAR
// model entry, as served by compose-manager's /v1/attestation/report.
type composeManagerEvidence struct {
	Actions     json.RawMessage `json:"actions"`
	ActionsHash string          `json:"actions_hash"`
	Nonce       string          `json:"nonce"`
	NonceSource string          `json:"nonce_source"`
	Quote       string          `json:"quote"`
	EventLog    string          `json:"event_log"`
	ReportData  string          `json:"report_data"`
	VMConfig    string          `json:"vm_config,omitempty"`
}

// ComposeManagerResult is the verification of the compose_manager_attestation
// of a NEAR model instance. NEAR's model CVM compose runs compose-manager,
// which starts the inference proxy and the model server after boot from
// files of nearai/cvm-compose-files, so neither is in RTMR3 or MRConfigID.
// compose-manager records each deployment in an action log and serves a
// second TDX quote whose REPORTDATA is sha256(canonical action log) followed
// by the client nonce.
type ComposeManagerResult struct {
	// Err is set when the evidence is missing or malformed.
	Err error
	// Quote is the verification of the compose-manager quote.
	Quote *TDXVerifyResult
	// TDErr is set when the quote is not from the TD of the instance quote.
	TDErr error
	// BindErr is set when REPORTDATA is not sha256(actions) || nonce.
	BindErr error
	// Actions is the action log that the quote binds when BindErr is nil.
	Actions []ComposeManagerAction
}

// VerifyComposeManager verifies the compose_manager_attestation of a NEAR
// model entry: the quote with verify, the same TD as instance (the verified
// quote of the entry), and REPORTDATA = sha256(canonical actions) || nonce.
// It returns nil for every other backend format.
func VerifyComposeManager(ctx context.Context, raw *RawAttestation, instance *TDXVerifyResult, nonce Nonce, verify TDXVerifier) *ComposeManagerResult {
	if raw.BackendFormat != FormatNear {
		return nil
	}
	quote, actions, digest, err := parseComposeManager(raw.ComposeManagerAttestation)
	if err != nil {
		return &ComposeManagerResult{Err: err}
	}
	r := &ComposeManagerResult{Quote: verify(ctx, quote), Actions: actions}
	if r.Quote.ParseErr != nil {
		return r
	}
	r.TDErr = sameTD(instance, r.Quote)
	want := append(digest[:], nonce[:]...)
	if subtle.ConstantTimeCompare(r.Quote.ReportData[:], want) != 1 {
		r.BindErr = fmt.Errorf("REPORTDATA %s is not sha256(actions) %s || nonce %s",
			hex.EncodeToString(r.Quote.ReportData[:]), hex.EncodeToString(digest[:]), nonce.Hex())
	}
	return r
}

// parseComposeManager decodes the evidence strictly and returns the quote,
// the typed actions and sha256 of the canonical action list.
func parseComposeManager(data []byte) (string, []ComposeManagerAction, [32]byte, error) {
	var digest [32]byte
	if len(bytes.TrimSpace(data)) == 0 {
		return "", nil, digest, errors.New("model entry has no compose_manager_attestation")
	}
	var ev composeManagerEvidence
	unknown, err := jsonstrict.UnmarshalObject(data, &ev, "compose_manager_attestation")
	if err != nil {
		return "", nil, digest, err
	}
	if len(unknown) != 0 {
		return "", nil, digest, fmt.Errorf("compose_manager_attestation has unknown members %v", unknown)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(ev.Actions, &items); err != nil || items == nil {
		return "", nil, digest, errors.New("compose_manager_attestation.actions: expected an array")
	}
	if len(items) > maxComposeManagerActions {
		return "", nil, digest, fmt.Errorf("compose_manager_attestation.actions: %d entries, more than %d", len(items), maxComposeManagerActions)
	}
	actions := make([]ComposeManagerAction, len(items))
	for i, item := range items {
		path := fmt.Sprintf("compose_manager_attestation.actions[%d]", i)
		unknown, err := jsonstrict.UnmarshalObject(item, &actions[i], path)
		if err != nil {
			return "", nil, digest, err
		}
		if len(unknown) != 0 {
			return "", nil, digest, fmt.Errorf("%s has unknown members %v", path, unknown)
		}
		if slices.Contains(actions[i].Services, nil) {
			return "", nil, digest, fmt.Errorf("%s.services: null is not permitted", path)
		}
	}
	canonical, err := canonicalJSON(ev.Actions)
	if err != nil {
		return "", nil, digest, fmt.Errorf("compose_manager_attestation.actions: %w", err)
	}
	return ev.Quote, actions, sha256.Sum256(canonical), nil
}

// canonicalJSON re-encodes data with object keys sorted, no whitespace and
// no HTML escaping: the encoding of compose-manager's canonicalize_actions
// and of Python's json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False).
func canonicalJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// sameTD returns an error unless cm has every TD measurement of instance:
// MRTD, MRSEAM, MRCONFIGID, MROWNER, MROWNERCONFIG and RTMR0-3. RTMR3
// carries the instance-id event, so it separates two instances of one image.
func sameTD(instance, cm *TDXVerifyResult) error {
	if instance == nil || instance.ParseErr != nil {
		return errors.New("the instance quote did not parse")
	}
	fields := []struct {
		name string
		a, b []byte
	}{
		{"MRTD", instance.MRTD, cm.MRTD},
		{"MRSEAM", instance.MRSeam, cm.MRSeam},
		{"MRCONFIGID", instance.MRConfigID, cm.MRConfigID},
		{"MROWNER", instance.MROwner, cm.MROwner},
		{"MROWNERCONFIG", instance.MROwnerConfig, cm.MROwnerConfig},
	}
	for i := range instance.RTMRs {
		fields = append(fields, struct {
			name string
			a, b []byte
		}{fmt.Sprintf("RTMR%d", i), instance.RTMRs[i][:], cm.RTMRs[i][:]})
	}
	for _, f := range fields {
		if len(f.a) == 0 || subtle.ConstantTimeCompare(f.a, f.b) != 1 {
			return fmt.Errorf("%s differs from the instance quote: %s, instance %s", f.name, hex.EncodeToString(f.b), hex.EncodeToString(f.a))
		}
	}
	return nil
}

// composeManagerImageRE matches an image reference pinned by digest.
var composeManagerImageRE = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// ComposeManagerImageRef reports whether s is an image reference pinned by
// sha256 digest, the form of compose_manager_image_allow entries.
func ComposeManagerImageRef(s string) bool { return composeManagerImageRE.MatchString(s) }

// ComposeManagerDeployments returns the compose file hashes that the log
// stages or brings up, and the compose-manager images it records starting.
// Every action that can run code names a value that must be allowed:
// compose_up and compose_stage (which pulls and builds) name a file_sha256,
// compose_manager_started names the image. compose_down, docker_restart,
// docker_clean (docker prune) and docker_evict (removes a model's cached
// weights) start nothing new. Any other action fails, and a log without a
// compose_manager_started entry does not attest the running compose-manager.
func ComposeManagerDeployments(actions []ComposeManagerAction) (files, images []string, err error) {
	for i := range actions {
		a := &actions[i]
		switch a.Action {
		case "compose_up", "compose_stage":
			if b, err := hex.DecodeString(a.FileSHA256); err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != a.FileSHA256 {
				return nil, nil, fmt.Errorf("actions[%d] %s: file_sha256 %q is not 32 bytes of lowercase hex", i, a.Action, a.FileSHA256)
			}
			files = appendNew(files, a.FileSHA256)
		case "compose_manager_started":
			if !ComposeManagerImageRef(a.Image) {
				return nil, nil, fmt.Errorf("actions[%d] compose_manager_started: image %q is not pinned by digest", i, a.Image)
			}
			images = appendNew(images, a.Image)
		case "compose_down", "docker_restart", "docker_clean", "docker_evict":
		default:
			return nil, nil, fmt.Errorf("actions[%d]: unknown action %q", i, a.Action)
		}
	}
	if len(images) == 0 {
		return nil, nil, errors.New("the action log has no compose_manager_started entry")
	}
	return files, images, nil
}

func appendNew(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
