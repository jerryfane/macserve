// Package maintenance observes native readiness; it never repairs host state.
package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
)

type Qualification struct {
	Schema                 int               `json:"schema"`
	ApprovedAt             time.Time         `json:"approved_at"`
	JobUID                 uint32            `json:"job_uid"`
	Boot                   string            `json:"boot"`
	InterfacesSHA256       string            `json:"interfaces_sha256"`
	PolicySHA256           string            `json:"policy_sha256"`
	RootRulesSHA256        string            `json:"root_rules_sha256"`
	AnchorRulesSHA256      string            `json:"anchor_rules_sha256"`
	BaselineSHA256         string            `json:"baseline_sha256"`
	BoundaryEvidenceSHA256 string            `json:"boundary_evidence_sha256"`
	Profiles               map[string]string `json:"profiles"`
}

// BoundaryEvidence is a protected operator attestation to actual probe artifacts,
// not independently verified proof that network tests occurred.
type BoundaryEvidence struct {
	Schema      int                  `json:"schema"`
	RecordedAt  time.Time            `json:"recorded_at"`
	JobUID      uint32               `json:"job_uid"`
	Boot        string               `json:"boot"`
	Probes      []Probe              `json:"probes"`
	Coexistence *CoexistenceEvidence `json:"coexistence"`
}
type Probe struct {
	Category                   string `json:"category"`
	ArtifactSHA256             string `json:"artifact_sha256"`
	Passed                     bool   `json:"passed"`
	Attempts                   int    `json:"attempts"`
	PFHitDelta                 int64  `json:"pf_hit_delta"`
	AuthorizedControlSuccesses int    `json:"authorized_control_successes"`
	CanaryReceipts             int    `json:"canary_receipts"`
}

// Observation is the pure evaluation seam. Production fills it only from bounded
// live checks, never from JSON or a caller-provided health boolean.
type Observation struct {
	JobUID                 uint32            `json:"job_uid"`
	Boot                   string            `json:"boot"`
	InterfacesSHA256       string            `json:"interfaces_sha256"`
	PolicySHA256           string            `json:"policy_sha256"`
	PFAnchor               string            `json:"pf_anchor"`
	RootRulesSHA256        string            `json:"root_rules_sha256"`
	AnchorRulesSHA256      string            `json:"anchor_rules_sha256"`
	BaselineSHA256         string            `json:"baseline_sha256"`
	BoundaryEvidenceSHA256 string            `json:"boundary_evidence_sha256,omitempty"`
	Profiles               map[string]string `json:"profiles"`
	PFEnabled              bool              `json:"pf_enabled"`
	LoopbackFiltered       bool              `json:"loopback_filtered"`
	IdentityValid          bool              `json:"identity_valid"`
	BaselineValid          bool              `json:"baseline_valid"`
	AccountedBytes         int64             `json:"accounted_bytes"`
	MemoryPressure         bool              `json:"memory_pressure"`
	Coexistence            *CoexistenceState `json:"coexistence,omitempty"`
}

func digest(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// Evaluate does no I/O. Every rejected observation returns an explicitly invalid
// health record suitable for immediate atomic publication.
func Evaluate(now time.Time, q Qualification, e BoundaryEvidence, o Observation) (controller.Health, error) {
	h := controller.Health{Schema: 1, JobUID: o.JobUID, CheckedAt: now, ExpiresAt: now.Add(30 * time.Second), AccountedBytes: -1, MemoryPressure: true}
	fail := func() (controller.Health, error) {
		return h, errors.New("maintenance qualification or live observation mismatch")
	}
	if q.Schema != 1 || e.Schema != 1 || q.JobUID < 501 || q.JobUID != o.JobUID || e.JobUID != o.JobUID || q.ApprovedAt.IsZero() || q.ApprovedAt.After(now) || e.RecordedAt.IsZero() || e.RecordedAt.After(q.ApprovedAt) || e.Boot != q.Boot || !o.PFEnabled || !o.LoopbackFiltered || !o.IdentityValid || !o.BaselineValid || o.AccountedBytes < 0 {
		return fail()
	}
	for _, pair := range [][2]string{{q.Boot, o.Boot}, {q.InterfacesSHA256, o.InterfacesSHA256}, {q.PolicySHA256, o.PolicySHA256}, {q.RootRulesSHA256, o.RootRulesSHA256}, {q.AnchorRulesSHA256, o.AnchorRulesSHA256}, {q.BaselineSHA256, o.BaselineSHA256}, {q.BoundaryEvidenceSHA256, o.BoundaryEvidenceSHA256}} {
		if !validDigest(pair[0]) || pair[0] != pair[1] {
			return fail()
		}
	}
	if e.Coexistence == nil || o.Coexistence == nil || o.Coexistence.RecordedAt.After(now) {
		return fail()
	}
	if err := ValidateCoexistenceEvidence(*e.Coexistence, *o.Coexistence, o.PFAnchor, o.PolicySHA256); err != nil {
		return fail()
	}
	if !maps.Equal(q.Profiles, o.Profiles) {
		return fail()
	}
	for id, d := range q.Profiles {
		if id == "" || !validDigest(d) {
			return fail()
		}
	}
	required := map[string]bool{"tcp_denial": false, "udp_denial": false, "approved_allow": false, "delegated_boundary": false, "unix_socket_boundary": false, "owner_unaffected": false, "owner_home_denial": false, "fast_switch": false, "reboot": false, "tool_profiles": false}
	for _, p := range e.Probes {
		seen, known := required[p.Category]
		if !known || seen || !p.Passed || !validDigest(p.ArtifactSHA256) || p.Attempts < 1 || p.PFHitDelta < 0 || p.AuthorizedControlSuccesses < 0 || p.CanaryReceipts < 0 {
			return fail()
		}
		if p.Category == "tcp_denial" && (p.Attempts < 3 || p.PFHitDelta == 0 || p.AuthorizedControlSuccesses == 0) {
			return fail()
		}
		if p.Category == "udp_denial" && (p.PFHitDelta == 0 || p.AuthorizedControlSuccesses == 0 || p.CanaryReceipts != 0) {
			return fail()
		}
		if p.Category == "owner_home_denial" && (p.AuthorizedControlSuccesses == 0 || p.CanaryReceipts != 0) {
			return fail()
		}
		required[p.Category] = true
	}
	for _, ok := range required {
		if !ok {
			return fail()
		}
	}
	h.PolicySHA256 = o.PolicySHA256
	h.InterfacesSHA256 = o.InterfacesSHA256
	h.BoundaryReceiptSHA256 = o.BoundaryEvidenceSHA256
	h.BoundaryValidated = true
	h.AccountedBytes = o.AccountedBytes
	h.MemoryPressure = o.MemoryPressure
	h.QualifiedProfiles = maps.Clone(o.Profiles)
	return h, nil
}
