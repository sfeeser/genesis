// Package scanner implements the L4 AST Analysis and Normalization boundary.
// It serves as the defensive shield and physical measuring device of the engine,
// parsing raw bytes, normalizing ASTs, and providing the deterministic evidence
// required by the Hexagonal Gates before any mutation is staged.
//
// Authority Class: 1 (Physical Authority / Verification)
package scanner

import (
	"context"
	"errors"

	"github.com/sfeeser/genesis/internal/identity"
)

// Sentinel boundary errors for the Scanner layer.
var (
	ErrParseFailure      = errors.New("failed to parse target source payload")
	ErrSymbolNotFound    = errors.New("target symbol not found in AST")
	ErrSignatureMismatch = errors.New("AST signature does not match expected physical constraint")
	ErrInvalidSyntax     = errors.New("synthesized source contains invalid Go syntax")
	ErrNormalization     = errors.New("failed to produce order-independent AST normalization")
)

const (
	// V1Normalization is the canonical algorithm identifier for AST reduction.
	// If the underlying go/ast traversal and normalization logic changes,
	// this version MUST be bumped to force L-ID recalculation across the registry.
	V1Normalization = "genesis.scanner.norm.v1"
)

// ParsedSymbol represents a verified, extracted symbol from the Go AST.
// It contains the normalized physical evidence required to compute
// the ContractID (C-ID) and LogicHash (L-ID).
type ParsedSymbol struct {
	NodeID        identity.NodeID
	AlgorithmID   string // Associates the payload with a specific normalization law (e.g., V1Normalization)
	Signature     string // The normalized canonical signature text (basis for C-ID)
	NormalizedAST []byte // The order-independent AST payload (basis for L-ID)
}

// Analyzer defines the L4 contract for verifying and extracting Go source code.
// It acts as a pure function over byte payloads, possessing zero filesystem authority.
type Analyzer interface {
	// Scan extracts and normalizes a specific symbol from a given byte payload.
	// It deterministically strips cosmetic changes (whitespace, comments)
	// to ensure stable L-ID generation across structural equivalents.
	Scan(ctx context.Context, source []byte, id identity.NodeID) (ParsedSymbol, error)

	// VerifySymbol ensures that a piece of raw synthesized source code
	// perfectly matches the expected physical identity and signature constraints.
	// It fails closed if the syntax is invalid or the signature drifts.
	VerifySymbol(ctx context.Context, source []byte, id identity.NodeID, expectedSignature string) (ParsedSymbol, error)
}
