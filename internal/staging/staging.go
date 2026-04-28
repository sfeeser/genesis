// Package staging implements the L5 Workspace Boundary for the Genesis Engine.
// It securely encapsulates filesystem access, module graph resolution, and 
// environment extraction, preventing path-traversal (including symlink escapes)
// and isolating physical I/O from cognitive tiers.
//
// Authority Class: 1 (Physical Authority / Workspace)
package staging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sfeeser/genesis/internal/identity"
	"github.com/sfeeser/genesis/internal/registry"
	"github.com/sfeeser/genesis/internal/spec"
)

// Sentinel boundary errors for the Staging layer.
var (
	ErrWorkspaceNotFound = errors.New("genesis workspace not found (missing go.mod or .genesis directory)")
	ErrFileNotFound      = errors.New("target file not found in workspace")
	ErrPathEscape        = errors.New("security violation: evaluated path escapes workspace boundary")
	ErrUnresolvedNode    = errors.New("cannot resolve physical package directory for given NodeID")
	ErrModuleMismatch    = errors.New("node module does not match current workspace module")
	ErrToolchainFailure  = errors.New("failed to execute physical go toolchain probe")
)

// Workspace defines the strictly governed L5 physical disk boundary.
type Workspace interface {
	LoadNormativeIntent(ctx context.Context) (spec.Book, error)
	ReadWorkspaceFile(ctx context.Context, relativePath string) ([]byte, error)
	CaptureEnvironment(ctx context.Context, buildTags, buildFlags []string) (registry.EnvironmentSentinel, error)
	ResolvePackageDir(id identity.NodeID) (string, error)
}

// localWorkspace is the concrete implementation of the physical OS boundary.
type localWorkspace struct {
	rootDir    string // Fully evaluated, symlink-resolved physical root
	moduleName string
}

// NewWorkspace initializes the physical boundary, resolving symlinks to prevent
// complex directory traversal attacks, and extracting the physical Go module identity.
func NewWorkspace(rootDir string) (Workspace, error) {
	cleanRoot := filepath.Clean(rootDir)
	evalRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to evaluate symlinks for root", ErrWorkspaceNotFound)
	}

	info, err := os.Stat(evalRoot)
	if err != nil || !info.IsDir() {
		return nil, ErrWorkspaceNotFound
	}

	modPath := filepath.Join(evalRoot, "go.mod")
	modBytes, err := os.ReadFile(modPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read go.mod", ErrWorkspaceNotFound)
	}

	moduleName := extractModulePath(modBytes)
	if moduleName == "" {
		return nil, fmt.Errorf("%w: go.mod contains no module declaration", ErrWorkspaceNotFound)
	}

	return &localWorkspace{
		rootDir:    evalRoot,
		moduleName: moduleName,
	}, nil
}

// LoadNormativeIntent reads, parses, and explicitly validates the specbook.yaml payload.
// It fails closed, returning an error if the normative intent violates L3 physics.
func (w *localWorkspace) LoadNormativeIntent(ctx context.Context) (spec.Book, error) {
	if err := ctx.Err(); err != nil {
		return spec.Book{}, err
	}

	payload, err := w.ReadWorkspaceFile(ctx, "specbook.yaml")
	if err != nil {
		return spec.Book{}, fmt.Errorf("failed to load normative intent file: %w", err)
	}

	var book spec.Book
	if err := yaml.Unmarshal(payload, &book); err != nil {
		return spec.Book{}, fmt.Errorf("invalid YAML syntax in specbook: %w", err)
	}

	if err := book.Valid(); err != nil {
		return spec.Book{}, fmt.Errorf("normative intent violates structural bounds: %w", err)
	}

	return book.Canonical(), nil
}

// ReadWorkspaceFile securely loads a file's bytes from the disk.
func (w *localWorkspace) ReadWorkspaceFile(ctx context.Context, relativePath string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	safePath, err := w.securePath(relativePath)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}

	return data, nil
}

// CaptureEnvironment executes physical system probes to extract the current toolchain
// and computes the cryptographic bounds of the workspace dependencies.
func (w *localWorkspace) CaptureEnvironment(ctx context.Context, buildTags, buildFlags []string) (registry.EnvironmentSentinel, error) {
	if err := ctx.Err(); err != nil {
		return registry.EnvironmentSentinel{}, err
	}

	env := registry.EnvironmentSentinel{
		GoVersion:     runtime.Version(),
		Goos:          runtime.GOOS,
		Goarch:        runtime.GOARCH,
		BuildTags:     buildTags,
		BuildFlags:    buildFlags,
		WorkspaceMode: "local",
	}

	// 1. Strict CGO Probe (Fail Closed)
	cmdCgo := exec.CommandContext(ctx, "go", "env", "CGO_ENABLED")
	cmdCgo.Dir = w.rootDir
	outCgo, err := cmdCgo.Output()
	if err != nil {
		return registry.EnvironmentSentinel{}, fmt.Errorf("%w: go env CGO_ENABLED failed", ErrToolchainFailure)
	}
	cgoVal := strings.TrimSpace(string(outCgo))
	if cgoVal == "1" {
		env.CgoEnabled = true
	} else if cgoVal != "0" {
		return registry.EnvironmentSentinel{}, fmt.Errorf("%w: unexpected CGO_ENABLED output '%s'", ErrToolchainFailure, cgoVal)
	}

	// 2. Cryptographic Module Graph (Fail Closed)
	cmdGraph := exec.CommandContext(ctx, "go", "mod", "graph")
	cmdGraph.Dir = w.rootDir
	outGraph, err := cmdGraph.Output()
	if err != nil {
		return registry.EnvironmentSentinel{}, fmt.Errorf("%w: go mod graph failed", ErrToolchainFailure)
	}
	graphHash := sha256.Sum256(outGraph)
	env.ModuleGraphHash = hex.EncodeToString(graphHash[:])

	// 3. Cryptographic sum (Tolerate missing only because of greenfield bootstrap)
	sumHash, err := w.hashPhysicalFile(ctx, "go.sum", true)
	if err != nil {
		return registry.EnvironmentSentinel{}, fmt.Errorf("failed to hash go.sum: %w", err)
	}
	env.GoSumHash = sumHash

	// 4. Validate and Canonicalize
	if err := env.Valid(); err != nil {
		return registry.EnvironmentSentinel{}, fmt.Errorf("environment capture violates bounds: %w", err)
	}

	return env.Canonical(), nil
}

// ResolvePackageDir deterministically computes the relative directory path 
// for a node, strictly stripping the module prefix to match the local filesystem layout.
func (w *localWorkspace) ResolvePackageDir(id identity.NodeID) (string, error) {
	if err := id.Valid(); err != nil {
		return "", fmt.Errorf("%w: invalid identity state", ErrUnresolvedNode)
	}
	if id.Module() != w.moduleName {
		return "", ErrModuleMismatch
	}

	pkgPath := id.PackagePath()
	
	// Exact match or strict subdirectory prefix match
	if pkgPath == w.moduleName {
		pkgPath = ""
	} else if strings.HasPrefix(pkgPath, w.moduleName+"/") {
		pkgPath = strings.TrimPrefix(pkgPath, w.moduleName+"/")
	}

	relPath := filepath.FromSlash(pkgPath)
	if !contained(w.rootDir, filepath.Join(w.rootDir, relPath)) {
		return "", ErrPathEscape
	}

	return relPath, nil
}

// --- Internal Security Bounds ---

// securePath constructs and fully evaluates a target path, explicitly rejecting
// absolute paths and returning ErrPathEscape if containment fails.
func (w *localWorkspace) securePath(relativePath string) (string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return "", ErrPathEscape
	}

	target := filepath.Join(w.rootDir, filepath.Clean(relativePath))
	
	evalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		// Tolerate missing file if staging a new file, but prove lexical containment
		if os.IsNotExist(err) {
			if !contained(w.rootDir, target) {
				return "", ErrPathEscape
			}
			return target, nil
		}
		return "", err
	}

	// Prove fully evaluated path remains inside the workspace
	if !contained(w.rootDir, evalTarget) {
		return "", ErrPathEscape
	}

	return evalTarget, nil
}

// contained performs native OS filepath math to prove the target resides within root.
func contained(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func extractModulePath(modBytes []byte) string {
	lines := bytes.Split(modBytes, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("module ")) {
			return string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("module "))))
		}
	}
	return ""
}

// hashPhysicalFile securely resolves and hashes a physical file.
func (w *localWorkspace) hashPhysicalFile(ctx context.Context, relativePath string, allowMissing bool) (string, error) {
	data, err := w.ReadWorkspaceFile(ctx, relativePath)
	if err != nil {
		if errors.Is(err, ErrFileNotFound) && allowMissing {
			return "", nil
		}
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
