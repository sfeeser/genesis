// Package graph implements the L7 Dependency Graph Resolution boundary.
// Authority Class: 2 (Logic / Orchestration Boundary)
package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/sfeeser/genesis/internal/identity"
	"github.com/sfeeser/genesis/internal/registry"
)

var (
	ErrResolutionFailed = errors.New("failed to mathematically resolve dependency graph")
	ErrSourceMissing    = errors.New("physical source file missing for graph resolution")
	ErrRegistryCorrupt  = errors.New("registry contains unprovable node identities")
	ErrTargetNotFound   = errors.New("target node not found in physical source")
)

type DependencyGraphEvidence struct {
	EnvironmentHash       string
	DependencyLogicHashes []string
}

type Workspace interface {
	ResolveSourceFile(id identity.NodeID) (string, error)
	ReadWorkspaceFile(ctx context.Context, relativePath string) ([]byte, error)
}

type Registry interface {
	ListNodes(ctx context.Context) ([]registry.NodeDetail, error)
	GetEnvironment(ctx context.Context) (registry.EnvironmentSentinel, error)
}

type Resolver interface {
	ResolveEvidence(ctx context.Context, id identity.NodeID) (DependencyGraphEvidence, error)
	ComputeDependencyHash(ctx context.Context, id identity.NodeID, evidence DependencyGraphEvidence) (string, error)
}

type subgraphResolver struct {
	store     Registry
	workspace Workspace
}

func NewResolver(store Registry, ws Workspace) Resolver {
	return &subgraphResolver{store: store, workspace: ws}
}

func (r *subgraphResolver) ResolveEvidence(ctx context.Context, id identity.NodeID) (DependencyGraphEvidence, error) {
	if err := ctx.Err(); err != nil {
		return DependencyGraphEvidence{}, err
	}

	// 1. Environment Baseline
	env, err := r.store.GetEnvironment(ctx)
	if err != nil {
		return DependencyGraphEvidence{}, fmt.Errorf("%w: %v", ErrResolutionFailed, err)
	}
	envHash := identity.ComputeLogicHash([]byte(env.ModuleGraphHash + env.GoSumHash))

	// 2. Physical Source Retrieval
	targetPath, err := r.workspace.ResolveSourceFile(id)
	if err != nil {
		return DependencyGraphEvidence{}, fmt.Errorf("%w: %v", ErrSourceMissing, err)
	}
	sourceBytes, err := r.workspace.ReadWorkspaceFile(ctx, targetPath)
	if err != nil {
		return DependencyGraphEvidence{}, fmt.Errorf("%w: %v", ErrSourceMissing, err)
	}

	// 3. AST & Binding Closure
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", sourceBytes, parser.ParseComments)
	if err != nil {
		return DependencyGraphEvidence{}, fmt.Errorf("%w: %v", ErrResolutionFailed, err)
	}

	importBindings := make(map[string]string)
	dotImports := make([]string, 0)
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return DependencyGraphEvidence{}, fmt.Errorf("%w: malformed import path: %v", ErrResolutionFailed, err)
		}
		
		if imp.Name != nil {
			if imp.Name.Name == "." {
				dotImports = append(dotImports, path)
				continue
			}
			if imp.Name.Name == "_" {
				continue 
			}
			importBindings[imp.Name.Name] = path
		} else {
			parts := strings.Split(path, "/")
			importBindings[parts[len(parts)-1]] = path
		}
	}

	// 4. Scoped Target Identification
	var targetDecl ast.Node
	for _, decl := range file.Decls {
		if match, _ := matchesDeclIdentity(decl, id); match {
			targetDecl = decl
			break
		}
	}
	if targetDecl == nil {
		return DependencyGraphEvidence{}, ErrTargetNotFound
	}

	// 5. Scoped Symbol Reference Extraction
	referencedSymbols := make(map[string]bool)
	unqualifiedIdents := make(map[string]bool)
	ast.Inspect(targetDecl, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if pkgIdent, ok := x.X.(*ast.Ident); ok {
				if fullPath, exists := importBindings[pkgIdent.Name]; exists {
					referencedSymbols[fullPath+"."+x.Sel.Name] = true
				}
			}
		case *ast.Ident:
			unqualifiedIdents[x.Name] = true
		}
		return true
	})

	// 6. Registry Mapping & Bidirectional Proof
	allNodes, err := r.store.ListNodes(ctx)
	if err != nil {
		return DependencyGraphEvidence{}, err
	}

	var deps []string
	targetCanon, err := id.Canonical()
	if err != nil {
		return DependencyGraphEvidence{}, fmt.Errorf("%w: failed to prove target identity: %v", ErrResolutionFailed, err)
	}
	targetPkg := id.PackagePath()

	for _, node := range allNodes {
		nodeCanon, err := node.NodeID.Canonical()
		if err != nil {
			return DependencyGraphEvidence{}, fmt.Errorf("%w: %v", ErrRegistryCorrupt, err)
		}
		if nodeCanon == targetCanon {
			continue
		}

		isDep := false
		nodePkg := node.NodeID.PackagePath()
		nodeSym := node.NodeID.Symbol()

		if nodePkg == targetPkg {
			isDep = unqualifiedIdents[nodeSym]
		} else {
			if referencedSymbols[nodePkg+"."+nodeSym] {
				isDep = true
			} else {
				for _, dotPath := range dotImports {
					if nodePkg == dotPath && unqualifiedIdents[nodeSym] {
						isDep = true
						break
					}
				}
			}
		}

		if isDep {
			if !isValidHex(node.LogicHash) {
				return DependencyGraphEvidence{}, fmt.Errorf("%w: node %s logic hash is corrupt", ErrResolutionFailed, nodeCanon)
			}
			deps = append(deps, node.LogicHash)
		}
	}

	return DependencyGraphEvidence{EnvironmentHash: envHash, DependencyLogicHashes: deps}, nil
}

func (r *subgraphResolver) ComputeDependencyHash(ctx context.Context, id identity.NodeID, evidence DependencyGraphEvidence) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if !isValidHex(evidence.EnvironmentHash) {
		return "", fmt.Errorf("invalid EnvironmentHash for D-ID computation")
	}
	
	canon, err := id.Canonical()
	if err != nil {
		return "", fmt.Errorf("failed to prove identity for D-ID: %w", err)
	}

	// Evidence Hardening: Re-validate logic hash integrity before sorting
	hashes := make([]string, 0, len(evidence.DependencyLogicHashes))
	for _, h := range evidence.DependencyLogicHashes {
		if !isValidHex(h) {
			return "", fmt.Errorf("D-ID evidence contains corrupt logic hash: %s", h)
		}
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	var buf strings.Builder
	buf.WriteString("LOCAL:")
	buf.WriteString(canon)
	buf.WriteString("|ENV:")
	buf.WriteString(evidence.EnvironmentHash)
	buf.WriteString("|DEPS:")
	buf.WriteString(strings.Join(hashes, ";"))

	hash := sha256.Sum256([]byte(buf.String()))
	return hex.EncodeToString(hash[:]), nil
}

func isValidHex(s string) bool {
	if len(s) != 64 { return false }
	_, err := hex.DecodeString(s)
	return err == nil
}

func matchesDeclIdentity(decl ast.Decl, target identity.NodeID) (bool, error) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if target.Kind() != "func" || d.Name.Name != target.Symbol() { return false, nil }
		hasRecv := d.Recv != nil && len(d.Recv.List) > 0
		if (target.ReceiverShape() == "none" && hasRecv) || (target.ReceiverShape() != "none" && !hasRecv) { return false, nil }
		if hasRecv {
			_, isPtr := d.Recv.List[0].Type.(*ast.StarExpr)
			if (target.ReceiverShape() == "ptr" && !isPtr) || (target.ReceiverShape() == "val" && isPtr) { return false, nil }
		}
		var arity int
		if d.Type != nil && d.Type.Params != nil {
			for _, field := range d.Type.Params.List {
				if len(field.Names) == 0 { arity++ } else { arity += len(field.Names) }
			}
		}
		return arity == target.Arity(), nil
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if target.Kind() == "type" && d.Tok == token.TYPE && s.Name.Name == target.Symbol() { return true, nil }
			case *ast.ValueSpec:
				for _, name := range s.Names {
					if (target.Kind() == "var" && d.Tok == token.VAR && name.Name == target.Symbol()) ||
						(target.Kind() == "const" && d.Tok == token.CONST && name.Name == target.Symbol()) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}
