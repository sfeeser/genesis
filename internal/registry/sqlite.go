// Package registry implements the L2 DNA Registry physical persistence layer.
// This file contains the SQLite-backed implementation of the Store contract,
// ensuring strictly ACID-compliant persistence and deterministic read ordering.
//
// Authority Class: 1 (Physical Authority / Persistence)
package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/sfeeser/genesis/internal/identity"
)

// Sentinel errors for the internal SQLite driver.
var (
	ErrDatabaseNotInitialized = errors.New("database not initialized")
	ErrCorruptRegistryState   = errors.New("registry contains corrupted physical state")
)

// sqliteStore is the concrete SQLite implementation of the L2 Store boundary.
type sqliteStore struct {
	db *sql.DB
}

// NewSQLiteStore initializes a new physical database connection.
func NewSQLiteStore(db *sql.DB) Store {
	return &sqliteStore{db: db}
}

// BootstrapAndReconcile establishes the baseline schema and physical toolchain environment.
func (s *sqliteStore) BootstrapAndReconcile(ctx context.Context, env EnvironmentSentinel) error {
	if err := env.Valid(); err != nil {
		return fmt.Errorf("cannot bootstrap with invalid environment: %w", err)
	}
	canonEnv := env.Canonical()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Enforce Physical Schema
	schema := `
	CREATE TABLE IF NOT EXISTS environment (
		id INTEGER PRIMARY KEY,
		go_version TEXT, goos TEXT, goarch TEXT, cgo_enabled BOOLEAN,
		build_tags TEXT, build_flags TEXT, workspace_mode TEXT,
		module_graph_hash TEXT, go_sum_hash TEXT
	);
	CREATE TABLE IF NOT EXISTS nodes (
		canonical_id TEXT PRIMARY KEY,
		kind TEXT, visibility TEXT, module TEXT, package_path TEXT,
		receiver_shape TEXT, symbol TEXT, arity INTEGER,
		maturity TEXT, contract_id TEXT, logic_hash TEXT, dependency_hash TEXT
	);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("schema initialization failed: %w", err)
	}

	// 2. Persist Canonical Environment
	tagsJSON, err := json.Marshal(canonEnv.BuildTags)
	if err != nil {
		return fmt.Errorf("failed to marshal build tags: %w", err)
	}
	flagsJSON, err := json.Marshal(canonEnv.BuildFlags)
	if err != nil {
		return fmt.Errorf("failed to marshal build flags: %w", err)
	}

	envQuery := `
	INSERT INTO environment (
		id, go_version, goos, goarch, cgo_enabled, build_tags, build_flags, 
		workspace_mode, module_graph_hash, go_sum_hash
	) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		go_version=excluded.go_version, goos=excluded.goos, goarch=excluded.goarch,
		cgo_enabled=excluded.cgo_enabled, build_tags=excluded.build_tags,
		build_flags=excluded.build_flags, workspace_mode=excluded.workspace_mode,
		module_graph_hash=excluded.module_graph_hash, go_sum_hash=excluded.go_sum_hash;
	`
	_, err = tx.ExecContext(ctx, envQuery,
		canonEnv.GoVersion, canonEnv.Goos, canonEnv.Goarch, canonEnv.CgoEnabled,
		string(tagsJSON), string(flagsJSON), canonEnv.WorkspaceMode,
		canonEnv.ModuleGraphHash, canonEnv.GoSumHash,
	)
	if err != nil {
		return fmt.Errorf("environment reconciliation failed: %w", err)
	}

	return tx.Commit()
}

// GetEnvironment retrieves the baseline physical constraints, returning a mathematically canonicalized sentinel.
func (s *sqliteStore) GetEnvironment(ctx context.Context) (EnvironmentSentinel, error) {
	var env EnvironmentSentinel
	var tagsJSON, flagsJSON string

	query := `SELECT go_version, goos, goarch, cgo_enabled, build_tags, build_flags, workspace_mode, module_graph_hash, go_sum_hash FROM environment WHERE id = 1`
	err := s.db.QueryRowContext(ctx, query).Scan(
		&env.GoVersion, &env.Goos, &env.Goarch, &env.CgoEnabled,
		&tagsJSON, &flagsJSON, &env.WorkspaceMode, &env.ModuleGraphHash, &env.GoSumHash,
	)
	
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EnvironmentSentinel{}, fmt.Errorf("%w: no environment baseline found", ErrDatabaseNotInitialized)
		}
		return EnvironmentSentinel{}, err
	}

	if err := json.Unmarshal([]byte(tagsJSON), &env.BuildTags); err != nil {
		return EnvironmentSentinel{}, fmt.Errorf("%w: build tags json corrupt: %v", ErrCorruptRegistryState, err)
	}
	if err := json.Unmarshal([]byte(flagsJSON), &env.BuildFlags); err != nil {
		return EnvironmentSentinel{}, fmt.Errorf("%w: build flags json corrupt: %v", ErrCorruptRegistryState, err)
	}

	if err := env.Valid(); err != nil {
		return EnvironmentSentinel{}, fmt.Errorf("%w: environment fails structural validation: %v", ErrCorruptRegistryState, err)
	}

	return env.Canonical(), nil
}

// GetNode rigorously retrieves a single physical node by its mathematical identity.
// It structurally validates the node details before returning.
func (s *sqliteStore) GetNode(ctx context.Context, id identity.NodeID) (NodeDetail, error) {
	canon, err := id.Canonical()
	if err != nil {
		return NodeDetail{}, fmt.Errorf("invalid identity query: %w", err)
	}

	var nd NodeDetail
	var mat string

	query := `SELECT maturity, contract_id, logic_hash, dependency_hash FROM nodes WHERE canonical_id = ?`
	err = s.db.QueryRowContext(ctx, query, canon).Scan(&mat, &nd.ContractID, &nd.LogicHash, &nd.DependencyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NodeDetail{}, ErrNodeNotFound
		}
		return NodeDetail{}, err
	}

	nd.NodeID = id
	nd.Maturity = Maturity(mat)

	// Mathematical proof of physical state bounds
	if err := nd.Valid(); err != nil {
		return NodeDetail{}, fmt.Errorf("%w: retrieved node violates bounds: %v", ErrCorruptRegistryState, err)
	}

	return nd, nil
}

// ListNodes retrieves all tracked physical nodes and guarantees a deterministic
// canonical sort order. It strictly fails closed if any row contains a corrupt identity or state.
func (s *sqliteStore) ListNodes(ctx context.Context) ([]NodeDetail, error) {
	query := `SELECT kind, visibility, module, package_path, receiver_shape, symbol, arity, maturity, contract_id, logic_hash, dependency_hash FROM nodes`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}
	defer rows.Close()

	// Temporary structure to map physical DB rows to rigorous L1 proofs.
	type sortableNode struct {
		canon string
		node  NodeDetail
	}
	var sortables []sortableNode

	for rows.Next() {
		var kind, vis, mod, pkgPath, recv, sym, mat, cid, lid, did string
		var arity int

		if err := rows.Scan(&kind, &vis, &mod, &pkgPath, &recv, &sym, &arity, &mat, &cid, &lid, &did); err != nil {
			return nil, fmt.Errorf("row scan failure: %w", err)
		}

		id, err := identity.NewNodeID(kind, vis, mod, pkgPath, recv, sym, arity)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse L1 identity from row (%s.%s): %v", ErrCorruptRegistryState, pkgPath, sym, err)
		}

		// Stage 9 Correction: Pre-compute canonical string and fail closed on proof error.
		canon, err := id.Canonical()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to canonicalize L1 identity from row: %v", ErrCorruptRegistryState, err)
		}

		nd := NodeDetail{
			NodeID:         id,
			Maturity:       Maturity(mat),
			ContractID:     cid,
			LogicHash:      lid,
			DependencyHash: did,
		}

		// Fail closed if the database row violates maturity physics or identity logic
		if err := nd.Valid(); err != nil {
			return nil, fmt.Errorf("%w: row (%s) violates bounds: %v", ErrCorruptRegistryState, canon, err)
		}

		sortables = append(sortables, sortableNode{
			canon: canon,
			node:  nd,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Mathematically guarantee deterministic ordering for downstream L7 Panoptic Audits.
	sort.SliceStable(sortables, func(i, j int) bool {
		return sortables[i].canon < sortables[j].canon
	})

	nodes := make([]NodeDetail, 0, len(sortables))
	for _, sn := range sortables {
		nodes = append(nodes, sn.node)
	}

	return nodes, nil
}

// Export dumps the physical registry state. (Hollow implementation per Stage 8 constraints)
func (s *sqliteStore) Export(ctx context.Context) error {
	return errors.New("Export: not yet implemented")
}

// BeginWorkset initiates a staged transaction boundary. (Hollow implementation per Stage 8 constraints)
func (s *sqliteStore) BeginWorkset(ctx context.Context, worksetID string, boundary SCCBoundary) (Workset, error) {
	return nil, errors.New("BeginWorkset: not yet implemented")
}
