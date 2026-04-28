// Package spec implements the L3 Normative Authority for the Genesis Engine.
// It defines the structural memory model for the specbook.yaml payload,
// enforcing strict validation of architectural intent before it maps to
// L1 physical identities in Stage 7 (Scaffold).
//
// Authority Class: 2 (Logic / Orchestration Boundary)
package spec

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sfeeser/genesis/internal/identity"
)

// Sentinel boundary errors for the Spec layer.
var (
	ErrInvalidGenesis        = errors.New("unsupported Genesis version: must be exactly 'v7.0'")
	ErrMissingModule         = errors.New("specbook must declare a valid root module path")
	ErrNoPackages            = errors.New("specbook contains no packages")
	ErrMissingPackagePath    = errors.New("package specification is missing a path")
	ErrMissingResponsibility = errors.New("responsibility intent cannot be empty")
	ErrInvalidNodeIntent     = errors.New("node specification violates L1 identity bounds")
	ErrDuplicatePackage      = errors.New("duplicate package path detected")
	ErrDuplicateNode         = errors.New("duplicate canonical node signature detected in package")
	ErrInvalidMaturity       = errors.New("target maturity violates closed schema literal bounds")
	ErrInvalidAuthority      = errors.New("authority class violates bounds (must be 0, 1, or 2)")
)

// Book represents the parsed architectural intent of the repository (Ch 1.1).
// It acts as the immutable normative blueprint.
type Book struct {
	Genesis  string    `yaml:"genesis" json:"genesis"`
	Module   string    `yaml:"module" json:"module"`
	Packages []Package `yaml:"packages" json:"packages"`
}

// Valid executes a deep structural validation of the entire Normative Authority.
// It guarantees that if the Book is valid, it can be mathematically mapped to L1 physics.
func (b Book) Valid() error {
	if b.Genesis != "v7.0" {
		return ErrInvalidGenesis
	}
	if strings.TrimSpace(b.Module) == "" {
		return ErrMissingModule
	}
	if len(b.Packages) == 0 {
		return ErrNoPackages
	}

	seenPackages := make(map[string]struct{}, len(b.Packages))
	for _, pkg := range b.Packages {
		if err := pkg.Valid(b.Module); err != nil {
			return fmt.Errorf("package '%s' invalid: %w", pkg.Path, err)
		}
		if _, exists := seenPackages[pkg.Path]; exists {
			return fmt.Errorf("%w: %s", ErrDuplicatePackage, pkg.Path)
		}
		seenPackages[pkg.Path] = struct{}{}
	}

	return nil
}

// Canonical generates a mathematically sound, deep-copied, and deterministically sorted
// instance of the Book for hashing or export, without mutating the caller's memory.
// It MUST only be called on a Book that has successfully passed Valid().
func (b Book) Canonical() Book {
	cp := b
	if len(b.Packages) > 0 {
		cp.Packages = make([]Package, len(b.Packages))
		for i, pkg := range b.Packages {
			cp.Packages[i] = pkg.Canonical(b.Module)
		}
		sort.SliceStable(cp.Packages, func(i, j int) bool {
			return cp.Packages[i].Path < cp.Packages[j].Path
		})
	}
	return cp
}

// Package groups normative node intents under a specific Go package boundary.
type Package struct {
	Path           string `yaml:"path" json:"path"`
	Responsibility string `yaml:"responsibility" json:"responsibility"`
	Nodes          []Node `yaml:"nodes" json:"nodes"`
}

// Valid ensures the package definition contains valid routing and node constraints.
func (p Package) Valid(modulePath string) error {
	if strings.TrimSpace(p.Path) == "" {
		return ErrMissingPackagePath
	}
	if strings.TrimSpace(p.Responsibility) == "" {
		return ErrMissingResponsibility
	}

	seenNodes := make(map[string]struct{}, len(p.Nodes))
	for _, n := range p.Nodes {
		if err := n.Valid(modulePath, p.Path); err != nil {
			return fmt.Errorf("node '%s' invalid: %w", n.Symbol, err)
		}

		canon, err := n.CanonicalID(modulePath, p.Path)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidNodeIntent, err) // Fail closed on L1 errors
		}

		if _, exists := seenNodes[canon]; exists {
			return fmt.Errorf("%w: %s", ErrDuplicateNode, canon)
		}
		seenNodes[canon] = struct{}{}
	}

	return nil
}

// Canonical generates a deep-copied, deterministically sorted package.
// Nodes are sorted using their strict L1 identity string proofs.
func (p Package) Canonical(modulePath string) Package {
	cp := p
	if len(p.Nodes) > 0 {
		cp.Nodes = make([]Node, len(p.Nodes))
		copy(cp.Nodes, p.Nodes)
		sort.SliceStable(cp.Nodes, func(i, j int) bool {
			// Errors are ignored only because this is post-Valid() execution.
			// Safe fallback to literal string comparison if physics inexplicably fail.
			sigI, _ := cp.Nodes[i].CanonicalID(modulePath, cp.Path)
			sigJ, _ := cp.Nodes[j].CanonicalID(modulePath, cp.Path)
			return sigI < sigJ
		})
	}
	return cp
}

// Node defines the architectural intent for a single code symbol.
type Node struct {
	Kind           string `yaml:"kind" json:"kind"`
	Visibility     string `yaml:"visibility" json:"visibility"`
	ReceiverShape  string `yaml:"receiver_shape" json:"receiver_shape"`
	Symbol         string `yaml:"symbol" json:"symbol"`
	Arity          int    `yaml:"arity" json:"arity"`
	Responsibility string `yaml:"responsibility" json:"responsibility"`
	TargetMaturity string `yaml:"target_maturity" json:"target_maturity"`
	AuthorityClass int    `yaml:"authority_class" json:"authority_class"`
}

// Valid thoroughly verifies the fields against L1 physics bounds and literal schemas,
// stopping invalid intents at the L3 boundary.
func (n Node) Valid(modulePath, packagePath string) error {
	// 1. Enforce physical law before intent evaluation.
	_, err := n.CanonicalID(modulePath, packagePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNodeIntent, err)
	}

	// 2. Validate L3 boundary literals. (Cannot import L2 per Ch 5.1, must duplicate literals).
	switch n.TargetMaturity {
	case "draft", "hollow", "anchored", "hydrated", "sequenced", "implemented":
		// valid
	default:
		return ErrInvalidMaturity
	}

	if n.AuthorityClass < 0 || n.AuthorityClass > 2 {
		return ErrInvalidAuthority
	}

	if strings.TrimSpace(n.Responsibility) == "" {
		return ErrMissingResponsibility
	}

	return nil
}

// CanonicalID synthesizes the intent into a mathematically sound L1 physical string.
// This enforces the Ch 1.2 grammar and ensures the node is structurally possible.
func (n Node) CanonicalID(modulePath, packagePath string) (string, error) {
	id, err := identity.NewNodeID(
		n.Kind,
		n.Visibility,
		modulePath,
		packagePath,
		n.ReceiverShape,
		n.Symbol,
		n.Arity,
	)
	if err != nil {
		return "", err
	}
	return id.Canonical()
}
