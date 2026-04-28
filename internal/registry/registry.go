// Package registry implements the L2 Physical Authority for the Genesis Engine.
// It strictly enforces the JSON-as-Law principle, SCC atomicity, and singleton
// environment validation, devoid of cognitive or path-based layer leaks.
//
// Authority Class: 1 (Physical Authority)
package registry

import (
	"context"
	"errors"
	"sort"

	"github.com/sfeeser/genesis/internal/identity"
)

// Sentinel boundary errors for the Registry layer.
var (
	ErrNodeNotFound     = errors.New("node not found in physical registry")
	ErrSCCViolation     = errors.New("mutation violates SCC atomicity constraints (coverage incomplete)")
	ErrEnvDrift         = errors.New("runtime environment drift detected against singleton metadata")
	ErrInvalidEnv       = errors.New("environment sentinel contains missing or invalid base attributes")
	ErrGateFailure      = errors.New("cannot commit: Hexagonal Gate receipt is invalid or incomplete")
	ErrWorksetPending   = errors.New("cannot flush: workset contains unvalidated nodes")
	ErrInvalidMaturity  = errors.New("invalid maturity state")
	ErrInvalidAuthority = errors.New("invalid authority class")
	ErrInvalidBoundary  = errors.New("SCC boundary is invalid or empty")
	ErrCoverageMismatch = errors.New("evaluated nodes do not exactly match the required SCC boundary")
	ErrInvalidDigest    = errors.New("cryptographic digest must be a 64-character hex string")
	ErrDuplicateNode    = errors.New("duplicate canonical NodeID detected in set")
	ErrMissingIdentity  = errors.New("node is missing required cryptographic identity for its maturity level")
)

// Maturity defines the closed-set lifecycle stages of a node (Ch 2.2).
type Maturity string

const (
	MaturityDraft       Maturity = "draft"
	MaturityHollow      Maturity = "hollow"
	MaturityAnchored    Maturity = "anchored"
	MaturityHydrated    Maturity = "hydrated"
	MaturitySequenced   Maturity = "sequenced"
	MaturityImplemented Maturity = "implemented" // Explicitly defined in Ch 2.2 and Ch 3.
)

// Valid enforces the closed enumeration.
func (m Maturity) Valid() error {
	switch m {
	case MaturityDraft, MaturityHollow, MaturityAnchored, MaturityHydrated, MaturitySequenced, MaturityImplemented:
		return nil
	default:
		return ErrInvalidMaturity
	}
}

// AuthorityClass represents the 0-2 restriction level of a node.
type AuthorityClass int

const (
	AuthClassCore     AuthorityClass = 0 // Foundational physics and identity
	AuthClassPhysical AuthorityClass = 1 // Structural graph and persistence boundaries
	AuthClassLogic    AuthorityClass = 2 // Orchestration, synthesis, and cognition
)

// Valid enforces the domain bounds of the authority class.
func (a AuthorityClass) Valid() error {
	if a < AuthClassCore || a > AuthClassLogic {
		return ErrInvalidAuthority
	}
	return nil
}

// EnvironmentSentinel mirrors the DB metadata singleton to prevent environment drift (Ch 2.1.3).
type EnvironmentSentinel struct {
	GoVersion       string
	Goos            string
	Goarch          string
	BuildTags       []string
	BuildFlags      []string
	CgoEnabled      bool
	GoSumHash       string
	ModuleGraphHash string
	WorkspaceMode   string
}

// Valid ensures the base parameters of the environment are structurally present.
func (e EnvironmentSentinel) Valid() error {
	if e.GoVersion == "" || e.Goos == "" || e.Goarch == "" || e.WorkspaceMode == "" {
		return ErrInvalidEnv
	}
	if e.GoSumHash != "" && !isSHA256Hex(e.GoSumHash) {
		return ErrInvalidDigest
	}
	if e.ModuleGraphHash != "" && !isSHA256Hex(e.ModuleGraphHash) {
		return ErrInvalidDigest
	}
	return nil
}

// Canonical generates a safe, deterministic copy of the sentinel with sorted slices
// without mutating the caller's underlying memory.
func (e EnvironmentSentinel) Canonical() EnvironmentSentinel {
	cp := e
	if len(e.BuildTags) > 0 {
		cp.BuildTags = make([]string, len(e.BuildTags))
		copy(cp.BuildTags, e.BuildTags)
		sort.Strings(cp.BuildTags)
	}
	if len(e.BuildFlags) > 0 {
		cp.BuildFlags = make([]string, len(e.BuildFlags))
		copy(cp.BuildFlags, e.BuildFlags)
		sort.Strings(cp.BuildFlags)
	}
	return cp
}

// SCCBoundary explicitly defines the Strongly Connected Component required for atomicity.
type SCCBoundary struct {
	ClusterID     string
	RequiredNodes []identity.NodeID
}

// Valid ensures the boundary is structurally sound and mathematically unique.
func (s SCCBoundary) Valid() error {
	if s.ClusterID == "" || len(s.RequiredNodes) == 0 {
		return ErrInvalidBoundary
	}

	seen := make(map[string]struct{}, len(s.RequiredNodes))
	for _, n := range s.RequiredNodes {
		if err := n.Valid(); err != nil {
			return err
		}
		canon, err := n.Canonical()
		if err != nil {
			return err
		}
		if _, exists := seen[canon]; exists {
			return ErrDuplicateNode
		}
		seen[canon] = struct{}{}
	}
	return nil
}

// GateReceipt is the deterministic proof that a mutation passed all Hexagonal Gates.
type GateReceipt struct {
	ClusterID        string
	GateDigest       string // Cryptographic anchor of the gate execution inputs
	EvaluatedNodes   []identity.NodeID
	PhysicsPassed    bool
	IdentityPassed   bool
	BehaviorPassed   bool
	CompilePassed    bool
	ReplayPassed     bool
	ComplexityPassed bool
}

// Valid proves the receipt is complete and cryptographically anchors its coverage
// against the exact required SCC boundary, utilizing strictly canonical L1 proofs.
func (g GateReceipt) Valid(boundary SCCBoundary) error {
	if !g.PhysicsPassed || !g.IdentityPassed || !g.BehaviorPassed ||
		!g.CompilePassed || !g.ReplayPassed || !g.ComplexityPassed {
		return ErrGateFailure
	}
	if g.ClusterID == "" || g.ClusterID != boundary.ClusterID {
		return ErrGateFailure
	}
	if !isSHA256Hex(g.GateDigest) {
		return ErrInvalidDigest
	}
	if len(g.EvaluatedNodes) != len(boundary.RequiredNodes) {
		return ErrCoverageMismatch
	}

	// Map the strictly unique required boundary
	requiredMap := make(map[string]struct{}, len(boundary.RequiredNodes))
	for _, n := range boundary.RequiredNodes {
		canon, err := n.Canonical()
		if err != nil {
			return err // L1 structural failure
		}
		requiredMap[canon] = struct{}{}
	}

	// Ensure evaluated nodes perfectly overlap the required set without self-duplicates
	seenEval := make(map[string]struct{}, len(g.EvaluatedNodes))
	for _, n := range g.EvaluatedNodes {
		canon, err := n.Canonical()
		if err != nil {
			return err // L1 structural failure
		}
		if _, exists := seenEval[canon]; exists {
			return ErrDuplicateNode
		}
		if _, exists := requiredMap[canon]; !exists {
			return ErrCoverageMismatch
		}
		seenEval[canon] = struct{}{}
	}

	return nil
}

// NodeDetail reflects the schema's core nodes table.
type NodeDetail struct {
	NodeID          identity.NodeID
	Maturity        Maturity
	Authority       AuthorityClass
	ContractID      string // C-ID Hex
	LogicHash       string // L-ID Hex
	DependencyHash  string // D-ID Hex
	BusinessPurpose string
}

// Valid executes a deep physical validation of the cross-boundary entity,
// enforcing strict identity hashing requirements based on node maturity.
func (nd NodeDetail) Valid() error {
	if err := nd.NodeID.Valid(); err != nil {
		return err
	}
	if err := nd.Maturity.Valid(); err != nil {
		return err
	}
	if err := nd.Authority.Valid(); err != nil {
		return err
	}

	// If hashes exist, they must strictly comply with hex bounds.
	if nd.ContractID != "" && !isSHA256Hex(nd.ContractID) {
		return ErrInvalidDigest
	}
	if nd.LogicHash != "" && !isSHA256Hex(nd.LogicHash) {
		return ErrInvalidDigest
	}
	if nd.DependencyHash != "" && !isSHA256Hex(nd.DependencyHash) {
		return ErrInvalidDigest
	}

	// Enforce progression physics based on maturity.
	switch nd.Maturity {
	case MaturityAnchored:
		if nd.ContractID == "" {
			return ErrMissingIdentity
		}
	case MaturityHydrated, MaturitySequenced, MaturityImplemented:
		if nd.ContractID == "" || nd.LogicHash == "" || nd.DependencyHash == "" {
			return ErrMissingIdentity
		}
	}

	return nil
}

// Store defines the physical authority contract (L2).
type Store interface {
	// BootstrapAndReconcile synchronizes the SQLite cache. As dictated by Ch 2.1.2:
	// If the canonical genome.json export exists and its hash differs from DB metadata,
	// this operation aggressively deletes and rebuilds the physical database.
	BootstrapAndReconcile(ctx context.Context, env EnvironmentSentinel) error

	// Export triggers a deterministic, sorted write to the canonical genome.json.
	Export(ctx context.Context) error

	// GetNode retrieves a fully hydrated physical node detail.
	GetNode(ctx context.Context, id identity.NodeID) (NodeDetail, error)

	// BeginWorkset opens a transaction for staging atomic SCC mutations.
	BeginWorkset(ctx context.Context, worksetID string, boundary SCCBoundary) (Workset, error)
}

// Workset represents a staged mutation boundary (Ch 2.1.3).
type Workset interface {
	// StageMutation proposes new physics for a node within the transactional workspace.
	StageMutation(ctx context.Context, quad identity.Quad, proposedMaturity Maturity) error
	
	// Commit flushes the workset to core tables if and only if all required SCC nodes
	// have been staged and the orchestrator provides a valid Hexagonal Gate receipt.
	Commit(ctx context.Context, receipt GateReceipt) error
	
	// Rollback safely aborts the mutation workset without physical side effects.
	Rollback(ctx context.Context) error
}

// --- Internal Structural Integrity Bounds ---

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
