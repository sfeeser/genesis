// Package surgeon implements the L6 Surgical Execution boundary.
// It is responsible for AST-aware code generation (Stage 8 Skeleton)
// and safe, targeted code injection (Stage 9 Synthesis). It enforces
// the Round-Trip Mutation Law to guarantee adjacent physical bounds
// remain completely uncorrupted during targeted synthesis.
//
// Authority Class: 1 (Physical Authority / Mutation)
package surgeon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"

	"github.com/sfeeser/genesis/internal/identity"
	"github.com/sfeeser/genesis/internal/scanner"
)

// Sentinel boundary errors for the Surgeon layer.
var (
	ErrHydrationFailed   = errors.New("failed to hydrate skeleton for physical node")
	ErrSpliceFailed      = errors.New("failed to safely splice synthesized logic into AST")
	ErrTargetMissing     = errors.New("target physical file is missing; cannot perform splice")
	ErrCorruptedAST      = errors.New("surgery resulted in invalid Go format or unparseable syntax")
	ErrAdjacentBleed     = errors.New("surgery corrupted adjacent AST nodes")
	ErrSymbolMissing     = errors.New("target symbol missing from physical AST; Stage 9 mutates but cannot hydrate")
	ErrSignatureMismatch = errors.New("synthesized signature diverges from structural expectations")
	ErrInvalidPayload    = errors.New("synthesized payload must contain exactly one matching declaration")
)

// MutationTarget represents the exact, validated physical instruction for L6 surgery.
type MutationTarget struct {
	NodeID            identity.NodeID
	PriorLogicHash    string
	ExpectedSignature string // Drives stub generation and post-splice verification
	TargetPath        string // Fully resolved relative workspace path (provided by Orchestrator/L5)
}

// SurgeryReceipt provides deterministic proof of a successful AST mutation.
type SurgeryReceipt struct {
	NodeID         identity.NodeID
	PriorLogicHash string
	NewSymbol      scanner.ParsedSymbol // Sourced from the final, merged, and formatted physical file
}

// Workspace defines the strict physical boundaries L6 requires from L5.
type Workspace interface {
	ReadWorkspaceFile(ctx context.Context, relativePath string) ([]byte, error)
	WriteWorkspaceFileAtomic(ctx context.Context, relativePath string, data []byte) error
}

// Chief defines the L6 contract for AST-aware codebase mutation.
type Chief interface {
	HydrateSkeleton(ctx context.Context, target MutationTarget) error
	SpliceLogic(ctx context.Context, target MutationTarget, synthesizedCode []byte) (SurgeryReceipt, error)
}

// astSurgeon is the concrete implementation of the physical mutation engine.
type astSurgeon struct {
	workspace Workspace
	scanner   scanner.Analyzer // Direct consumption of the upgraded L4 contract
}

// NewChief initializes the surgical execution environment.
func NewChief(ws Workspace, sc scanner.Analyzer) Chief {
	return &astSurgeon{
		workspace: ws,
		scanner:   sc,
	}
}

// HydrateSkeleton mechanically generates a hollow, compilable signature.
// It fails closed if the physical file exists but lacks the target NodeID.
func (s *astSurgeon) HydrateSkeleton(ctx context.Context, target MutationTarget) error {
	existingSource, err := s.workspace.ReadWorkspaceFile(ctx, target.TargetPath)
	if err == nil {
		_, scanErr := s.scanner.Scan(ctx, existingSource, target.NodeID)
		if scanErr != nil {
			return fmt.Errorf("%w: existing file lacks required symbol: %v", ErrHydrationFailed, scanErr)
		}
		return nil
	}

	stub, err := buildMechanicalStub(target.NodeID, target.ExpectedSignature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHydrationFailed, err)
	}

	formatted, err := format.Source([]byte(stub))
	if err != nil {
		return fmt.Errorf("%w: formatting failed for skeleton: %v", ErrHydrationFailed, err)
	}

	if err := s.workspace.WriteWorkspaceFileAtomic(ctx, target.TargetPath, formatted); err != nil {
		return fmt.Errorf("%w: atomic write failed: %v", ErrHydrationFailed, err)
	}

	return nil
}

// SpliceLogic performs targeted Stage 9 surgery according to the Round-Trip Mutation Law.
func (s *astSurgeon) SpliceLogic(ctx context.Context, target MutationTarget, synthesizedCode []byte) (SurgeryReceipt, error) {
	// 1. Validate incoming payload before touching the disk.
	if err := verifySynthesizedPayload(synthesizedCode, target.NodeID); err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	// 2. Read existing physical state. Stage 9 fails closed if missing.
	existingSource, err := s.workspace.ReadWorkspaceFile(ctx, target.TargetPath)
	if err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: %v", ErrTargetMissing, err)
	}

	// 3. Scan pre-surgery adjacents to establish baseline physics.
	preAdjacents, err := s.scanner.ScanAll(ctx, existingSource)
	if err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: could not establish adjacent baseline: %v", ErrSpliceFailed, err)
	}

	// 4. Splice AST bytes mechanically using strict NodeID physics.
	mergedSource, err := spliceASTBytes(existingSource, target.NodeID, synthesizedCode)
	if err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: %v", ErrCorruptedAST, err)
	}

	// 5. Format the merged output.
	formatted, err := format.Source(mergedSource)
	if err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: format failed post-splice: %v", ErrCorruptedAST, err)
	}

	// 6. Verify Target Identity and Signature.
	finalSymbol, err := s.scanner.VerifySymbol(ctx, formatted, target.NodeID, target.ExpectedSignature)
	if err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: %v", ErrSignatureMismatch, err)
	}

	// 7. Prove Adjacents are Unchanged (No Bleed).
	postAdjacents, err := s.scanner.ScanAll(ctx, formatted)
	if err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: post-splice scan failed: %v", ErrSpliceFailed, err)
	}
	if err := verifyAdjacentsUnchanged(target.NodeID, preAdjacents, postAdjacents); err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: %v", ErrAdjacentBleed, err)
	}

	// 8. Commit physical law to disk.
	if err := s.workspace.WriteWorkspaceFileAtomic(ctx, target.TargetPath, formatted); err != nil {
		return SurgeryReceipt{}, fmt.Errorf("%w: atomic write failed: %v", ErrSpliceFailed, err)
	}

	return SurgeryReceipt{
		NodeID:         target.NodeID,
		PriorLogicHash: target.PriorLogicHash,
		NewSymbol:      finalSymbol,
	}, nil
}

// --- Internal Surgical Instruments ---

func extractPackageName(id identity.NodeID) string {
	parts := bytes.Split([]byte(id.PackagePath()), []byte("/"))
	return string(parts[len(parts)-1])
}

// buildMechanicalStub utilizes the exact L3 expected signature.
func buildMechanicalStub(id identity.NodeID, expectedSignature string) (string, error) {
	if expectedSignature == "" {
		return "", errors.New("cannot build physical stub without an expected signature")
	}

	var b bytes.Buffer
	b.WriteString(fmt.Sprintf("package %s\n\n", extractPackageName(id)))

	switch id.Kind() {
	case "func":
		b.WriteString(expectedSignature)
		b.WriteString(" {\n\tpanic(\"genesis: hollow node\")\n}\n")
	case "type":
		b.WriteString(fmt.Sprintf("type %s struct{}\n", id.Symbol()))
	case "const":
		b.WriteString(fmt.Sprintf("const %s = 0\n", id.Symbol()))
	case "var":
		b.WriteString(fmt.Sprintf("var %s interface{}\n", id.Symbol()))
	default:
		return "", fmt.Errorf("unknown node kind: %s", id.Kind())
	}

	return b.String(), nil
}

// verifySynthesizedPayload parses the raw LLM output, enforcing that it contains
// exactly one declaration and matches the expected physical identity.
func verifySynthesizedPayload(payload []byte, target identity.NodeID) error {
	pkgWrap := append([]byte("package temp_splice\n\n"), payload...)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", pkgWrap, parser.ParseComments)
	if err != nil {
		return errors.New("synthesized code is not valid Go syntax")
	}

	if len(file.Decls) != 1 {
		return fmt.Errorf("expected exactly 1 declaration, found %d", len(file.Decls))
	}

	match, err := matchesDeclIdentity(file.Decls[0], target)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("synthesized declaration shape does not match target physical NodeID")
	}

	return nil
}

// matchesDeclIdentity deeply verifies that an AST declaration mathematically maps to the NodeID,
// strictly including arity extraction to prevent overload cross-corruption.
func matchesDeclIdentity(decl ast.Decl, target identity.NodeID) (bool, error) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if target.Kind() != "func" || d.Name.Name != target.Symbol() {
			return false, nil
		}
		
		hasRecv := d.Recv != nil && len(d.Recv.List) > 0
		if target.ReceiverShape() == "none" && hasRecv {
			return false, nil
		}
		if target.ReceiverShape() != "none" && !hasRecv {
			return false, nil
		}
		if hasRecv {
			_, isPtr := d.Recv.List[0].Type.(*ast.StarExpr)
			if target.ReceiverShape() == "ptr" && !isPtr {
				return false, nil
			}
			if target.ReceiverShape() == "val" && isPtr {
				return false, nil
			}
		}

		// Arity Proof: Count exactly how many parameters the signature defines.
		var arity int
		if d.Type != nil && d.Type.Params != nil {
			for _, field := range d.Type.Params.List {
				if len(field.Names) == 0 {
					arity++ // Unnamed parameter (e.g. `func(int, string)`)
				} else {
					arity += len(field.Names) // Named parameters (e.g. `func(a, b int)`)
				}
			}
		}
		if arity != target.Arity() {
			return false, nil
		}

		return true, nil
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if ts, ok := spec.(*ast.TypeSpec); ok {
				if target.Kind() == "type" && ts.Name.Name == target.Symbol() {
					return true, nil
				}
			}
			if vs, ok := spec.(*ast.ValueSpec); ok {
				for _, name := range vs.Names {
					if (target.Kind() == "var" || target.Kind() == "const") && name.Name == target.Symbol() {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

// spliceASTBytes mechanically locates a target by exact physical identity and swaps the byte payload.
// It fails closed if the target symbol does not physically exist in the file.
func spliceASTBytes(original []byte, target identity.NodeID, newCode []byte) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", original, parser.ParseComments)
	if err != nil {
		return nil, errors.New("cannot parse existing source file")
	}

	var targetNode ast.Node
	for _, decl := range file.Decls {
		match, err := matchesDeclIdentity(decl, target)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating AST declaration: %w", err)
		}
		if match {
			targetNode = decl
			break
		}
	}

	if targetNode == nil {
		return nil, ErrSymbolMissing // Fail closed: Stage 9 mutates existing physical bounds.
	}

	start := fset.Position(targetNode.Pos()).Offset
	end := fset.Position(targetNode.End()).Offset

	var buf bytes.Buffer
	buf.Write(original[:start])
	buf.Write(newCode)
	buf.Write(original[end:])

	return buf.Bytes(), nil
}

// verifyAdjacentsUnchanged mathematically proves that no non-target nodes were altered.
func verifyAdjacentsUnchanged(target identity.NodeID, pre []scanner.ParsedSymbol, post []scanner.ParsedSymbol) error {
	targetCanon, err := target.Canonical()
	if err != nil {
		return err
	}

	preMap := make(map[string][]byte)
	for _, p := range pre {
		canon, err := p.NodeID.Canonical()
		if err != nil {
			return err
		}
		if canon != targetCanon {
			preMap[canon] = p.NormalizedAST
		}
	}

	postMap := make(map[string][]byte)
	for _, p := range post {
		canon, err := p.NodeID.Canonical()
		if err != nil {
			return err
		}
		if canon != targetCanon {
			postMap[canon] = p.NormalizedAST
		}
	}

	if len(preMap) != len(postMap) {
		return fmt.Errorf("adjacent node count changed (expected %d, got %d)", len(preMap), len(postMap))
	}

	for idCanon, preAST := range preMap {
		postAST, exists := postMap[idCanon]
		if !exists {
			return fmt.Errorf("adjacent node deleted: %s", idCanon)
		}
		if !bytes.Equal(preAST, postAST) {
			return fmt.Errorf("adjacent node logic mutated: %s", idCanon)
		}
	}

	return nil
}
