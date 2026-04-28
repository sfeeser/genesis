# Genesis Engine v7.0 

Chapter 1: The Manifesto
Chapter 2: The DNA Registry
Chapter 3: The Metamorphosis Pipeline
Chapter 4: Control Surface & CLI
Chapter 5: The Internal Constitution
Chapter 6: The Cognitive Tier Split

**Chapter 1: The Manifesto**

Genesis is a **Bounded Synthesis System** that transforms architectural intent into a deterministic engineering discipline. It operates on the principle that **the Specification is the Permanent Asset** (the Soul) while generated code is a transient, disposable liability. By utilizing a local-first Registry Engine, Genesis enforces architectural physics and type-safety through rigorous verification, ensuring every materialization is stable and reproducible.

**1.1. The Authority Stack**  
Genesis enforces a three-tier hierarchy of authority to eliminate architectural drift:

1. **The Specbook (Normative Authority)**: The immutable source of truth for architectural intent and requirements.  
2. **The Registry Engine (Physical Authority)**: A local-first relational database (`.genesis/genome.db`) that serves as the single source of physical truth, graph structure, convergence metadata, and SCC boundaries.  
3. **The Canvas (Observational Authority)**: A read-only visualization providing real-time telemetry of the synthesis process (see Chapter 4).

**1.2. The Identity Quad**  
Every node is anchored by four immutable dimensions:

- **NodeID**: `kind.visibility.module.package.receiver.symbol.arity` (canonical string form)  
- **C-ID (Contract)**: Canonical signature and generic constraints  
- **L-ID (Logic)**: SHA-256 hash of the normalized, order-independent AST  
- **D-ID (Dependency)**: Recursive digest of the transitive dependency graph and explicit build context (GOOS, GOARCH, tags, and toolchain)

**1.3. The DNA Registry**  
The Registry replaces flat manifests with a relational model to manage complexity at scale:

- **Structural Genome**: Persists the Identity Quad, dependency edges, and SCC clusters — the "Hard Physics" layer.  
- **Semantic Index**: An advisory vector index for Search-by-Intent (all selections must be validated by the Structural Genome).  
- **Canonical Audit Export**: `genome.json` is the primary, git-auditable source of truth; the SQLite database is treated as a rebuildable runtime cache.

**1.4. The Agentic Development Pipeline**  
Genesis follows a strictly governed execution flow:

1. **Preparation (Stages 1–6)**: Discovery, drift detection, and graph analysis.  
2. **Scaffold (Stage 7)**: Construction of the authoritative Scaffold Graph.  
3. **Skeleton (Stage 8)**: Agent-driven hollow materialization followed by immediate registry enrichment.  
4. **Synthesis (Stage 9)**: A tool-calling Intelligent Coding Agent performs targeted surgery under strict authority boundaries and SCC atomicity rules.

**1.5. The Hexagonal Acceptance Envelope**  
Every change must pass six gates before being committed: Physics, Identity Coherence, Behavioral Invariants, Compilation, Canonical Replay, and Cost/Complexity. The developer controls and observes the entire process through the CLI Control Surface and the optional Canvas.

---

**Chapter 2: The DNA Registry**

The Registry serves as the **Physical Authority** and persistent memory of the Genesis Engine. It follows the **JSON-as-Law** principle: `genome.json` is the single canonical, Git-auditable source of truth. The SQLite database (`.genesis/genome.db`) is treated as a high-performance, rebuildable runtime cache.

**2.1. Registry Physical Architecture**

**2.1.1. Canonical Audit Export (save-genome)**  
Every mutation operation that reaches a committed state automatically triggers a deterministic, sorted, and pretty-printed export to `.genesis/genome.json`. This file contains the complete state of the Genome, Scaffold Graph, and semantic vectors (base64-encoded). `genome.json` **must** be committed to the repository. `.genesis/genome.db` is listed in `.gitignore`.

**2.1.2. Rebuild Rule**  
On startup of any Genesis command, the engine checks for `genome.json`. If the file exists and its `export_hash` does not match the database metadata, the engine deletes the current DB and fully rebuilds it from the JSON. This guarantees that `git pull` from teammates instantly synchronizes the entire project state.

**2.1.3. Transactional Enforcement**  
To guarantee SCC atomicity and environment safety:  
1. **Environment Sentinel**: Before any mutation, the current runtime context (GOOS, GOARCH, build tags, etc.) is verified against the `metadata` singleton. Mismatches are forbidden.  
2. **Mutation Workset**: Changes are never written directly to core tables. The orchestrator stages mutations in the `mutation_worksets` table.  
3. **Finalization Gate**: A trigger ensures that if any node in a Strongly Connected Component is mutated, the entire cluster must be present with valid state transitions and must pass all Hexagonal Gates before an atomic flush occurs.

**2.2. The Hardened Schema**

```sql
-- 1. Metadata (Environment Singleton)
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    go_version TEXT NOT NULL,
    goos TEXT NOT NULL,
    goarch TEXT NOT NULL,
    build_tags_json TEXT NOT NULL,
    build_flags_json TEXT NOT NULL,
    cgo_enabled INTEGER NOT NULL CHECK (cgo_enabled IN (0,1)),
    go_sum_hash TEXT NOT NULL,
    module_graph_hash TEXT NOT NULL,
    workspace_mode TEXT NOT NULL,
    last_sequence_hash TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT 'v7',
    export_hash TEXT,           -- SHA-256 of genome.json
    export_timestamp DATETIME
);

-- 2. Nodes (Core Genome)
CREATE TABLE nodes (
    node_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    visibility TEXT NOT NULL,
    module_path TEXT NOT NULL,
    package_path TEXT NOT NULL,
    receiver TEXT NOT NULL CHECK (receiver IN ('none', 'pointer', 'value')),
    symbol_name TEXT NOT NULL,
    arity INTEGER NOT NULL,
    contract_id TEXT,
    canonical_contract TEXT,
    logic_hash TEXT,
    dependency_hash TEXT,
    maturity TEXT NOT NULL CHECK (maturity IN ('draft', 'hollow', 'anchored', 'hydrated', 'sequenced', 'implemented')),
    authority_class INTEGER NOT NULL CHECK (authority_class IN (0,1,2)),
    gene TEXT,
    business_purpose TEXT,
    last_audit_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 3. Graph & SCC Model
CREATE TABLE graph_revisions (
    graph_hash TEXT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE edges (
    source_node_id TEXT NOT NULL,
    target_node_id TEXT,
    target_external_symbol TEXT,
    edge_kind TEXT NOT NULL,
    graph_hash TEXT NOT NULL,
    PRIMARY KEY (source_node_id, target_node_id, target_external_symbol, edge_kind, graph_hash),
    FOREIGN KEY (source_node_id) REFERENCES nodes(node_id),
    FOREIGN KEY (graph_hash) REFERENCES graph_revisions(graph_hash)
);

CREATE TABLE scc_cluster_defs (
    cluster_id TEXT NOT NULL,
    graph_hash TEXT NOT NULL,
    authority_partitioned INTEGER NOT NULL,
    node_count INTEGER NOT NULL,
    PRIMARY KEY (cluster_id, graph_hash),
    FOREIGN KEY (graph_hash) REFERENCES graph_revisions(graph_hash)
);

CREATE TABLE scc_cluster_members (
    cluster_id TEXT NOT NULL,
    graph_hash TEXT NOT NULL,
    node_id TEXT NOT NULL,
    PRIMARY KEY (cluster_id, graph_hash, node_id),
    FOREIGN KEY (cluster_id, graph_hash) REFERENCES scc_cluster_defs(cluster_id, graph_hash),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id)
);

-- 4. Semantic Provenance
CREATE TABLE inference_profiles (
    profile_id TEXT PRIMARY KEY,
    tier TEXT NOT NULL CHECK (tier IN ('FAST', 'DEEP', 'EMBED')),
    model_name TEXT NOT NULL,
    model_revision TEXT NOT NULL,
    dimensions INTEGER NOT NULL,
    distance_metric TEXT NOT NULL DEFAULT 'cosine',
    summary_schema_version TEXT NOT NULL,
    summary_prompt_hash TEXT NOT NULL,
    chunking_policy TEXT NOT NULL,
    normalization_policy TEXT NOT NULL
);

CREATE TABLE semantic_records (
    record_id INTEGER PRIMARY KEY,
    node_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    summary_hash TEXT NOT NULL,
    is_stale INTEGER NOT NULL CHECK (is_stale IN (0,1)),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id),
    FOREIGN KEY (profile_id) REFERENCES inference_profiles(profile_id)
);

CREATE VIRTUAL TABLE semantic_index USING vss0(
    record_id INTEGER,
    vector(3072)
);

-- 5. Scaffold Graph (Authoritative Blueprint)
CREATE TABLE scaffold_revisions (
    revision_hash TEXT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    specbook_hash TEXT NOT NULL
);

CREATE TABLE scaffold_nodes (
    scaffold_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('package', 'file', 'node')),
    package_path TEXT NOT NULL,
    file_path TEXT,
    symbol TEXT,
    responsibility TEXT NOT NULL,
    maturity TEXT NOT NULL,
    authority_class INTEGER NOT NULL CHECK (authority_class IN (0,1,2)),
    embedding BLOB,                    -- 3072-dim vector as blob
    revision_hash TEXT NOT NULL,
    FOREIGN KEY (revision_hash) REFERENCES scaffold_revisions(revision_hash)
);

CREATE TABLE scaffold_edges (
    source_scaffold_id TEXT NOT NULL,
    target_scaffold_id TEXT NOT NULL,
    edge_kind TEXT NOT NULL,
    weight INTEGER DEFAULT 50,
    revision_hash TEXT NOT NULL,
    PRIMARY KEY (source_scaffold_id, target_scaffold_id, edge_kind, revision_hash),
    FOREIGN KEY (revision_hash) REFERENCES scaffold_revisions(revision_hash)
);

CREATE TABLE scaffold_scc_defs (
    cluster_id TEXT NOT NULL,
    revision_hash TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    PRIMARY KEY (cluster_id, revision_hash),
    FOREIGN KEY (revision_hash) REFERENCES scaffold_revisions(revision_hash)
);

CREATE TABLE scaffold_scc_members (
    cluster_id TEXT NOT NULL,
    revision_hash TEXT NOT NULL,
    scaffold_id TEXT NOT NULL,
    PRIMARY KEY (cluster_id, revision_hash, scaffold_id),
    FOREIGN KEY (cluster_id, revision_hash) REFERENCES scaffold_scc_defs(cluster_id, revision_hash),
    FOREIGN KEY (scaffold_id) REFERENCES scaffold_nodes(scaffold_id)
);

-- 6. Mutation Workset (Solver Workspace)
CREATE TABLE mutation_worksets (
    workset_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    proposed_maturity TEXT NOT NULL,
    proposed_logic_hash TEXT,
    proposed_dependency_hash TEXT,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'validated', 'committed', 'failed')),
    PRIMARY KEY (workset_id, node_id),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id)
);
```

**2.3. Agent-Facing Go Models**

```go
// internal/registry/models.go + internal/synthesis/tools.go

type NodeDetail struct {
    NodeID          string `json:"node_id"`
    Maturity        string `json:"maturity"`
    Authority       int    `json:"authority_class"`
    Contract        string `json:"contract"`
    BusinessPurpose string `json:"business_purpose"`
    CurrentCode     string `json:"current_code,omitempty"`
}

type NodeHistory struct {
    SynthesisAttempts int      `json:"synthesis_attempts"`
    GrowthHistory     []int    `json:"growth_history"`   // e.g. [7, 8, 9]
    Regressions       []string `json:"regressions"`      // regression events
    LastSuccess       *Attempt `json:"last_success"`
}

type BlastRadius struct {
    DirectImpact []string `json:"direct_impact"`
    Downstream   []string `json:"downstream"`
    RiskLevel    string   `json:"risk_level"`
    Coreness     string   `json:"coreness"` // "x-y" format
}

type RelatedNode struct {
    NodeID   string `json:"node_id"`
    Relation string `json:"relation"` // calls / called_by / same_scc / same_package
    Maturity string `json:"maturity"`
    Distance int    `json:"distance"`
}

type HealthSummary struct {
    OverallScore  float64 `json:"overall_score"`
    StuckNodes    int     `json:"stuck_nodes"`
    SCCsInTension int     `json:"sccs_in_tension"`
    DriftNodes    int     `json:"drift_nodes"`
    Message       string  `json:"message"`
}

type SearchResult struct {
    ScaffoldID string  `json:"scaffold_id"`
    Score      float64 `json:"score"`
    Snippet    string  `json:"snippet"`
}
```


---



**Here is the refined, consolidated Chapter 3:**

---

**Chapter 3: The Metamorphosis Pipeline**

Genesis transforms architectural intent into working code through a strictly governed, transactional pipeline. CLI commands serve as thin entrypoints that invoke specific stages. In the future, `evoke:` directives in the SpecBook will allow fully automated execution.

### CLI Commands

#### `init`
- **Purpose**: Bootstrap the Registry (Physical Authority).
- **What it does**: Creates `.genesis/` and an empty `genome.db` with all schemas (relational + VSS).
- **Destructive?** Yes (use `--force` to overwrite).

#### `enrich`
- **Purpose**: Build semantic understanding of the codebase.
- **What it does**: Delta AST scan; enriches nodes with `business_purpose` and 3072-dim embeddings (preferring `scaffolding.yaml` when available).
- **Destructive?** No.

#### `verify`
- **Purpose**: Detect Genome Drift.
- **What it does**: Compares stored `logic_hash` against current AST (ignores cosmetic changes).
- **Destructive?** No.

#### `graph`
- **Purpose**: Compute Blast Radius and coreness.
- **What it does**: Builds full call graph and inverted dependencies.
- **Destructive?** No.

#### `locate` (alias: `loc`)
- **Purpose**: Natural-language discovery.
- **What it does**: Vector search against the Semantic Index; returns results + Blast Radius.
- **Destructive?** No.

#### `ping`
- **Purpose**: Validate LLM/embedding providers.
- **Destructive?** No.

#### `hydrate` (alias: `hyd`)
- **Purpose**: Materialize skeleton code.
- **What it does**: Generates packages, files, signatures, and imports from the Scaffold Graph; runs `enrich` immediately after.
- **Destructive?** Yes.

#### `scaffold`, `synthesize`, `gen`
- Higher-level orchestrators for Stages 7–9.

### Core Processing Stages

| Stage | Name              | Description                                      | Visual (Canvas)                  |
|-------|-------------------|--------------------------------------------------|----------------------------------|
| 1     | **Anchor** (`init`) | Bootstrap Registry                               | ☐ → ✅                           |
| 2     | **Sight** (`enrich`) | Semantic enrichment of codebase                 | ☐ → ✅                           |
| 3     | **Verify**        | Detect drift between Registry and disk           | ☐ → ✅                           |
| 4     | **Graph**         | Build call graph + Blast Radius                  | ☐ → ✅                           |
| 5     | **Discovery** (`locate`) | Semantic search                              | N/A                              |
| 6     | **Gatekeeper**    | Validate SpecBook quality                        | ☐ → ✅ or ❌                     |
| 7     | **Scaffold**      | Build authoritative Scaffold Graph               | Dashed white (ghost)             |
| 8     | **Skeleton**      | Generate hollow but compilable code              | Translucent white + pulse        |
| 9     | **Synthesis**     | Intelligent implementation loop                  | Yellow → Green solid             |

**Maturity Legend (Stages 7–9)**

| Maturity     | Visual                     | Meaning                              |
|--------------|----------------------------|--------------------------------------|
| Conceptual   | Dashed white (ghost)       | Intent recorded, no code yet         |
| Hollow       | Translucent white + pulse  | Signatures generated, compilable     |
| Anchored     | Blue halo                  | Contract frozen                      |
| Hydrating    | Yellow + vibration         | Agent actively synthesizing          |
| Implemented  | Green solid                | Fully synthesized and verified       |

### Stages 7–9: The Intelligent Coding Agent

These are the **only** stages where the tool-calling DEEP LLM (the coding agent) is permitted to operate. All prior stages are deterministic and mechanical.

#### Core Principles
- The agent operates **exclusively via tool calls** (MCP-style). It never receives giant context dumps.
- Every response ends with a `=== GENESIS CONTINUATION DIRECTIVE ===` block.
- The orchestrator uses this directive as the single source of truth for the next action.
- SCCs are **atomic mutation units** — the agent must handle the entire cluster together.
- Every materialization is immediately followed by `enrich` to keep the Registry synchronized.
- The **Scaffold Graph** is the single authoritative blueprint from Stage 7 onward.

#### Agent Tools (only allowed interfaces)
1. `get_node_history(node_id)`
2. `get_original_spec(node_id)`
3. `get_related_nodes(node_id, limit)`
4. `get_project_health()`
5. `get_previous_llm_reasoning(node_id)`
6. `get_blast_radius(node_id)` (includes coreness `x-y`)
7. `get_node_code(node_id)`

#### Node Biography (recorded per node)
- `growth_history`: array of stage numbers
- `synthesis_attempts`: count
- `synthesis_outcome_history`: array of results
- `regressions`: array of failure events
- `coreness` (`x-y`), `project_health_score`, etc.

#### Stage 7 – Scaffold
**Trigger**: `genesis scaffold` or `genesis gen`  
The agent builds the complete Scaffold Graph (packages → files → symbols) from the SpecBook, writes it to the Registry, and exports `scaffolding.yaml`.  
**Exit**: Scaffold Graph becomes the single source of truth. Continuation Directive specifies next action (`hydrate` or pause).

#### Stage 8 – Skeleton
**Trigger**: `genesis hydrate`  
The agent walks the Scaffold Graph topologically and materializes hollow but compilable code (signatures + `// TODO`).  
Every successful write is followed by `enrich`.  
**Exit**: All nodes at `hollow` maturity and compilable.

#### Stage 9 – Synthesis
**Trigger**: `genesis synthesize` or `genesis gen`  
The agent walks the graph (SCCs atomic), uses tools to gather context, generates implementation logic, and performs targeted surgery via the Surgical Inner Loop.  
On success: `enrich` → update maturity to `implemented`.  
After every attempt the agent issues a Continuation Directive.  
**Loop prevention**: Max 3 failures per node/SCC → surface UNSAT with evidence.

**Termination**: All nodes reach `implemented` or explicit UNSAT.

**Continuation Directive Format** (example)
```
=== GENESIS CONTINUATION DIRECTIVE ===
next_action: continue | retry | pause | unsat
target_nodes: [...]
reason: ...
===
```

---


---

**Here is the merged, polished Chapter 5:**

---

**Chapter 4: Control Surface & CLI**

The Control Surface is the developer’s primary interface to Genesis. It enforces a strict separation between **Architectural Intent** (SpecBook) and **Surgical Execution** (Stages 7–9), following a “Fire and Observe” model that minimizes cognitive load.

### 5.1. Greenfield Protocol

To bootstrap or evolve a project, provide the specifications in specbook.yaml  Genesis automatically detects and resumes from existing state:

```bash
# Fresh (greenfield) project
./gen init 

# Existing project (resumes automatically)
./gen enrich
```

- If `.genesis/genome.json` exists, it is used as the primary source of truth and the SQLite database is rebuilt on demand.
- The `--target` directory is scanned for a `genome.json` to resume previous work.

### 5.2. CLI Commands

All commands are thin entrypoints registered in the root Cobra shell. They delegate to the Orchestrator and never contain business logic.

| Command       | Purpose                              | Key Behavior                          | Destructive? |
|---------------|--------------------------------------|---------------------------------------|--------------|
| `init`        | Bootstrap Registry                   | Creates `.genesis/` + empty DB        | Yes (`--force`) |
| `enrich`      | Semantic enrichment                  | Delta scan + embeddings               | No           |
| `verify`      | Detect Genome Drift                  | Logic hash comparison                 | No           |
| `graph`       | Build call graph                     | Blast Radius & coreness               | No           |
| `locate` (`loc`) | Semantic search                   | Vector search + Blast Radius          | No           |
| `ping`        | Validate LLM providers               | Connectivity + PONG test              | No           |
| `scaffold`    | Stage 7 – Build Scaffold Graph       | Authoritative blueprint               | No           |
| `hydrate` (`hyd`) | Stage 8 – Skeleton                | Hollow code materialization           | Yes          |
| `synthesize`  | Stage 9 – Intelligent synthesis      | Tool-calling agent loop               | Yes          |
| `gen`         | Full pipeline (Stages 7–9)           | Recommended main command              | Yes          |

### 5.3. The Apex (Root Shell Boundary)

The `cmd/saayn` package is the **only** component allowed to touch OS-level inputs. It enforces the following invariants:

- Loads `.env` and CLI flags.
- Injects a single deterministic `auditUnix` timestamp for the entire transaction.
- Owns the root `context.Context` with graceful cancellation (`SIGINT` → exit 130).
- All internal packages (L1–L12) are forbidden from calling `os.Getenv`, accessing flags, or performing raw I/O.
- Commands must be explicitly registered in Cobra `init()` blocks. Unregistered commands may not mutate state.

### 5.4. Deterministic Exit Codes

| Code | Meaning                        | Trigger |
|------|--------------------------------|---------|
| 0    | Success                        | Normal completion |
| 1    | Panic / Invariant violation    | Internal error |
| 2    | Determinant / Config error     | Missing keys, invalid `.env` |
| 126  | Access / Preflight failure     | Permission or validation error |
| 130  | Interrupted                    | SIGINT or context cancellation |

### 5.5. Mechanical Trace (Observability)

```plaintext
🧬 GENESIS v7.0
--------------------------------------------------------------------------------
📜 SpecBook:   14 nodes defined in specbook.yaml
📦 Genome:     Loaded from .genesis/genome.json (export_hash: a1b2c3...)
🏗️  Scaffold:   Building authoritative graph... ✓ (8 packages, 27 nodes)

🌱 STAGE 8 — SKELETON
--------------------------------------------------------------------------------
[08/27] internal/worker/worker.go → Translucent white + pulse

🌱 STAGE 9 — SYNTHESIS
--------------------------------------------------------------------------------
[03/12] PROCESSING: internal/worker/worker.go
    🔬 Node: saayn.Worker.Start
    📋 Responsibility: Starts background task processor with context cancellation
    🛠️  Synthesizing...
       ├─ get_node_history() → 0 prior attempts
       ├─ get_blast_radius() → coreness 12-3 (medium risk)
       └─ Generating implementation...
    ✅ Success → Green solid (static)
    💾 enrich() completed | Logic hash: d4e5f6...
```

**Additional Guarantees**
- Any command that writes source code must pass a **round-trip check** (Scanner must be able to read back the exact same `NodeID` and `logic_hash`).
- After every mutation reaching a committed state, `save-genome` is automatically invoked.

---

This merged chapter is now concise, self-contained, and consistent in tone with Chapters 1–3. It absorbs the best parts of the original Chapter 5 and Chapter 8 while eliminating overlap and redundancy.

**Recommendation**: We can now delete the old Chapter 8 entirely. The manifesto flow is clean:  
**Ch1 → Ch2 → Ch3 → Ch5** (with Ch4 removed as previously recommended).

Ready for Chapter 6 (Internal Constitution) or any further adjustments.

# **Chapter 5: The Internal Constitution**

Chapter 5 is the **Internal Constitution** of Genesis. It defines the exact package structure and dependency rules that the engine must obey when materializing its own source code. This chapter serves as the ground truth for the Scaffold Graph in Stage 7 and enables true self-hosting.
### **5.1. Canonical allowed_imports (Closed World)**
The engine enforces a strict, unidirectional import graph. Only the following imports are permitted:

| Package                  | Layer | Allowed Imports (Downstream Only)                              |
|--------------------------|-------|----------------------------------------------------------------|
| `internal/identity`      | L1    | (root — no imports)                                            |
| `internal/registry`      | L2    | `internal/identity`                                            |
| `internal/spec`          | L3    | `internal/identity`                                            |
| `internal/scanner`       | L4    | `internal/identity`, `internal/spec`                           |
| `internal/staging`       | L5    | `internal/identity`, `internal/registry`, `internal/spec`      |
| `internal/surgeon`       | L6    | `internal/identity`, `internal/registry`, `internal/scanner`, `internal/staging` |
| `internal/audit`         | L7    | `internal/identity`, `internal/registry`, `internal/spec`, `internal/scanner`, `internal/staging` |
| `internal/auditlog`      | L8    | `internal/identity`, `internal/registry`                       |
| `internal/metamorphosis` | L9    | `internal/identity`, `internal/registry`, `internal/spec`, `internal/staging`, `internal/surgeon`, `internal/audit`, `internal/auditlog` |
| `internal/orchestrator`  | L10   | `internal/identity`, `internal/registry`, `internal/spec`, `internal/metamorphosis` |
| `internal/telemetry`     | L11   | `internal/identity`, `internal/registry`, `internal/auditlog`, `internal/orchestrator` |
| `internal/mcp`           | L12   | `internal/identity`, `internal/orchestrator`                   |
| `cmd/saayn`              | L13   | `internal/orchestrator`, `internal/mcp`                        |

### **5.2. Deterministic Build Order**

The Scaffold Graph in Stage 7 must produce exactly this topological order for self-materialization:

1. `identity`  
2. `registry`  
3. `spec`  
4. `scanner`  
5. `staging`  
6. `surgeon` & `audit` (siblings)  
7. `auditlog`  
8. `metamorphosis`  
9. `orchestrator`  
10. `telemetry`  
11. `mcp`  
12. `cmd/saayn` (apex)

Stages 8 and 9 follow this order when Genesis is synthesizing its own codebase.

### **5.3. Corrected Grammar Standard**

- **receiver** field values: `none` | `value` | `pointer`
- **NodeID grammar**: `kind.visibility.module.package.receiver.symbol.arity`
- All normative references in the SpecBook and Scaffold Graph use this exact format.

### **5.4. Forbidden Patterns (Architectural Crimes)**

- **Circular Feedback**: `metamorphosis` → `orchestrator` (the state machine must remain a servant to the orchestrator).
- **Boundary Bleed**: Any `internal/` package importing `telemetry` or `mcp` (these are observers only).
- **Registry Bypass**: Any package performing direct file I/O or database access outside of `staging` or `registry`.

### **5.5. Rationale: The Self-Sustaining Loop**

By defining Genesis using this exact topology, the engine can treat its own source code as a valid **SpecBook**.  

- If the `identity` package changes, Stage 7 (Scaffold) and Stage 9 (Synthesis) will automatically detect the drift and re-materialize every layer above it.  
- The ultimate proof of the Greenfield Protocol is that Genesis can successfully surround-hydrate its own `metamorphosis` package without breaking the DAG or violating any rule in this chapter.


### **Chapter 6: The Cognitive Tier Split**

The Genesis Engine treats external intelligence as a non-deterministic dependency. To protect the deterministic core, reasoning is physically partitioned into isolated tiers.

#### **6.1 Tier Separation & Isolation**

* **Tier 1: FAST (Sensory)** — Used only for read-oriented work (analysis, enrichment, semantic indexing).
* **Tier 2: DEEP (Reasoning)** — Used only for write-oriented work (logic generation, architectural repair, synthesis).
* **Tier 3: EMBED (Vectorization)** — Used only for embedding generation and similarity search.

**Boundary Law:** The cognition layer **MUST NOT** import `registry`, `surgeon`, or mutate any `IdentityQuad`. All outputs are untrusted and must be validated by the Scanner (L4) before any state change.

#### **6.2 Tier Determinants & .env Configuration**

Configuration is loaded from a `.env` file in the project root (or `.genesis/.env`). Tier-local variables take precedence.

| Variable                  | Type    | Role                              | Fallback                  |
|---------------------------|---------|-----------------------------------|---------------------------|
| `GENESIS_FAST_MODEL`      | String  | Model for Sensory Tier            | —                         |
| `GENESIS_DEEP_MODEL`      | String  | Model for Reasoning Tier          | —                         |
| `GENESIS_EMBED_MODEL`     | String  | Model for embeddings              | —                         |
| `GENESIS_FAST_API_KEY`    | Secret  | Credential for FAST tier          | `GENESIS_API_KEY`         |
| `GENESIS_DEEP_API_KEY`    | Secret  | Credential for DEEP tier          | `GENESIS_API_KEY`         |
| `GENESIS_EMBED_API_KEY`   | Secret  | Credential for EMBED tier         | `GENESIS_API_KEY`         |
| `GENESIS_API_DELAY`       | Integer | Minimum delay between calls (ms)  | 0                         |

The Root Shell (`cmd/saayn`) loads and validates the `.env` file at startup. All internal packages receive only typed configuration structs — never raw environment variables.

#### **6.3 Temporal Guardrail (Sequential Spacing)**

Each tier enforces rate limiting via a reservation system to prevent abuse and respect provider limits.

The implementation **MUST** compute:
```go
reservedSlot := lastCall + delay
if now > reservedSlot {
    reservedSlot = now
}
```
Requests wait until the reserved slot. On cancellation, rollback is allowed only if the slot was not advanced.

#### **6.4 Connectivity Invariant (PONG)**

Before any Convergence Cycle, each tier is verified:
1. Send micro-prompt: `"System check. Respond only with PONG."`
2. Response must equal `"PONG"` (after trimming whitespace).
3. Any failure blocks the cycle and returns a clear error.

#### **6.5 Reference Authority**

All LLM client code **MUST** follow the official Go GenAI SDK:
https://pkg.go.dev/google.golang.org/genai





