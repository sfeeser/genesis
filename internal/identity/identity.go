// Package identity defines the L1 physical law of the Genesis Engine.
// It strictly enforces the closed-world Identity Quad and canonical NodeID
// formatting. All higher-level packages rely on this structural integrity.
//
// Authority Class: 0 (Core Physics)
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Sentinel validation errors for deterministic audit feedback.
var (
	ErrInvalidNodeID   = errors.New("invalid NodeID format (must be 7 dot-separated segments)")
	ErrMalformedField  = errors.New("field contains illegal characters or violates structural bounds")
	ErrInvalidReceiver = errors.New("illegal receiver shape (must be none, ptr, or val)")
	ErrNegativeArity   = errors.New("arity cannot be negative")
	ErrNonCanonical    = errors.New("parsed string does not match canonical output")
	ErrInvalidEscape   = errors.New("invalid percent-escape sequence in segment")
	ErrInvalidContract = errors.New("C-ID must be a 64-character hex string")
	ErrInvalidQuadHash = errors.New("L-ID and D-ID must be 64-character hex strings")
)

// NodeID represents the immutable canonical identifier for a graph node.
// Grammar: kind.visibility.module.package.receiver_shape.symbol.arity
type NodeID struct {
	kind          string
	visibility    string
	module        string
	packagePath   string
	receiverShape string
	symbol        string
	arity         int
}

// Valid executes full structural and ASCII boundaries on the current state.
func (n NodeID) Valid() error {
	if !isStrictLowerAlphanumeric(n.kind) || !isStrictLowerAlphanumeric(n.visibility) {
		return ErrMalformedField
	}
	if !isPathSafe(n.module) || !isPathSafe(n.packagePath) {
		return ErrMalformedField
	}
	if !isStrictAlphanumeric(n.symbol) {
		return ErrMalformedField
	}
	if n.receiverShape != "none" && n.receiverShape != "ptr" && n.receiverShape != "val" {
		return ErrInvalidReceiver
	}
	if n.arity < 0 {
		return ErrNegativeArity
	}
	return nil
}

// NewNodeID safely constructs a NodeID, requiring full structural validation.
func NewNodeID(kind, visibility, module, packagePath, receiverShape, symbol string, arity int) (NodeID, error) {
	n := NodeID{
		kind:          kind,
		visibility:    visibility,
		module:        module,
		packagePath:   packagePath,
		receiverShape: receiverShape,
		symbol:        symbol,
		arity:         arity,
	}
	if err := n.Valid(); err != nil {
		return NodeID{}, err
	}
	return n, nil
}

// ParseNodeID deterministically extracts and validates a NodeID.
// It enforces the Round-Trip Law: the parsed node MUST reserialize to the exact input.
func ParseNodeID(raw string) (NodeID, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 7 {
		return NodeID{}, ErrInvalidNodeID
	}

	arity, err := strconv.Atoi(parts[6])
	if err != nil {
		return NodeID{}, ErrInvalidNodeID
	}

	mod, err := unescapeSegment(parts[2])
	if err != nil {
		return NodeID{}, err
	}

	pkg, err := unescapeSegment(parts[3])
	if err != nil {
		return NodeID{}, err
	}

	n, err := NewNodeID(parts[0], parts[1], mod, pkg, parts[4], parts[5], arity)
	if err != nil {
		return NodeID{}, err
	}

	// The Round-Trip Law: Prove perfect parse/string symmetry.
	canonical, err := n.Canonical()
	if err != nil || canonical != raw {
		return NodeID{}, ErrNonCanonical
	}

	return n, nil
}

// Canonical generates the mathematically sound string identity.
// It returns an error if the internal state is invalid, providing a safe proof path.
func (n NodeID) Canonical() (string, error) {
	if err := n.Valid(); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(n.kind)
	b.WriteByte('.')
	b.WriteString(n.visibility)
	b.WriteByte('.')
	b.WriteString(escapeSegment(n.module))
	b.WriteByte('.')
	b.WriteString(escapeSegment(n.packagePath))
	b.WriteByte('.')
	b.WriteString(n.receiverShape)
	b.WriteByte('.')
	b.WriteString(n.symbol)
	b.WriteByte('.')
	b.WriteString(strconv.Itoa(n.arity))

	return b.String(), nil
}

// String provides a safe, non-panicking implementation for fmt.Stringer.
// Code requiring proof of validity should use Canonical().
func (n NodeID) String() string {
	c, err := n.Canonical()
	if err != nil {
		return "<invalid_node_id>"
	}
	return c
}

// Getters expose immutable fields to L2+.
func (n NodeID) Kind() string          { return n.kind }
func (n NodeID) Visibility() string    { return n.visibility }
func (n NodeID) Module() string        { return n.module }
func (n NodeID) PackagePath() string   { return n.packagePath }
func (n NodeID) ReceiverShape() string { return n.receiverShape }
func (n NodeID) Symbol() string        { return n.symbol }
func (n NodeID) Arity() int            { return n.arity }

// Quad anchors a node across the four immutable physical dimensions.
type Quad struct {
	nodeID         NodeID
	contractID     string
	logicHash      string
	dependencyHash string
}

// NewQuad structurally validates all four identity dimensions.
func NewQuad(n NodeID, cid, lid, did string) (Quad, error) {
	if err := n.Valid(); err != nil {
		return Quad{}, err
	}
	if !isSHA256Hex(cid) {
		return Quad{}, ErrInvalidContract
	}
	if !isSHA256Hex(lid) || !isSHA256Hex(did) {
		return Quad{}, ErrInvalidQuadHash
	}

	return Quad{
		nodeID:         n,
		contractID:     cid,
		logicHash:      lid,
		dependencyHash: did,
	}, nil
}

// Quad Getters
func (q Quad) NodeID() NodeID         { return q.nodeID }
func (q Quad) ContractID() string     { return q.contractID }
func (q Quad) LogicHash() string      { return q.logicHash }
func (q Quad) DependencyHash() string { return q.dependencyHash }

// ComputeLogicHash calculates a deterministic SHA-256 digest from a provided byte slice.
// Normalization MUST be performed by the L4 Scanner prior to calling this primitive.
func ComputeLogicHash(normalizedPayload []byte) string {
	hash := sha256.Sum256(normalizedPayload)
	return hex.EncodeToString(hash[:])
}

// --- Hand-Rolled ASCII Validation & Escaping (L1 Performance/Determinism) ---

func isStrictLowerAlphanumeric(s string) bool {
	if s == "" { return false }
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func isStrictAlphanumeric(s string) bool {
	if s == "" { return false }
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func isPathSafe(s string) bool {
	if s == "" { return false }
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '/' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 { return false }
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// escapeSegment deterministically encodes dots and percents.
func escapeSegment(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	return strings.ReplaceAll(s, ".", "%2E")
}

// unescapeSegment rigidly parses only canonical %25 and %2E sequences.
func unescapeSegment(s string) (string, error) {
	if !strings.ContainsRune(s, '%') {
		return s, nil
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return "", ErrInvalidEscape
			}
			code := s[i+1 : i+3]
			if code == "25" {
				b.WriteByte('%')
			} else if code == "2E" {
				b.WriteByte('.')
			} else {
				return "", ErrInvalidEscape
			}
			i += 2 // skip the hex digits
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

// ComputeContractID deterministically hashes the canonical signature payload.
// It relies on the existing L1 logic hash primitive to guarantee cryptographic uniformity.
func ComputeContractID(signature string) string {
	return ComputeLogicHash([]byte(signature))
}

