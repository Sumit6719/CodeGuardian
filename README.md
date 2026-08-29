# CodeGuardian

> **Model-Independent, Security-First, Permission-Aware AI Software Engineering Platform**  
> *CSE Major Research & Development Project*

---

## 1. What is CodeGuardian?

CodeGuardian is an experimental AI software engineering system designed around a foundational principle: **Never blindly trust an AI-generated action.**

While modern generative models excel at code synthesis, bug detection, and refactoring proposals, executing AI-generated commands directly against local filesystems or operating systems introduces serious risks—including silent code corruption, unauthorized path escapes, and the accidental overwrite of critical secrets. 

CodeGuardian decouples the **AI Planner** from the **Execution Layer** by placing a deterministic, policy-based security gatekeeper between the model's proposals and the operating system.

---

## 2. Why It Exists (The Problem)

Standard AI coding prototypes (such as basic agent loops utilizing function calling) follow an unconstrained pattern:

```
[LLM Function Call] ──► [Direct OS / fs Execution]
```

This model suffers from critical vulnerabilities:
1. **Blind Trust**: If an LLM proposes modifying `.env` or system configurations, the runtime executes it without independent risk assessment.
2. **Path Traversal**: Raw string paths can escape workspace roots (`../../etc/passwd` or `C:\Windows\...`).
3. **Destructive Overwrites**: In-place writes permanently destroy existing code if the model hallucinates, crashes, or produces truncated syntax.
4. **No Auditability**: Console logs are ephemeral and lack structured evidence or cryptographic change tracking.

CodeGuardian addresses these limitations through an independent, deterministic security pipeline.

---

## 3. Architecture & Security Pipeline

CodeGuardian enforces an unbypassable, multi-stage governance pipeline:

```
AI Model Proposal
      │
      ▼
1. Input Normalization & Validation
      │
      ▼
2. PathGuard (Canonical resolution & workspace boundary containment)
      │
      ▼
3. Target Sensitivity Analyzer (CRITICAL / HIGH / MEDIUM / LOW)
      │
      ▼
4. Blast Radius Estimator (LOCAL / MODULE / WORKSPACE / SYSTEM)
      │
      ▼
5. Risk Engine (Deterministic scoring independent of LLM self-assessment)
      │
      ▼
6. Policy Engine (Rule-based decision: ALLOW | ASK_USER | BLOCK)
      │
      ├──────────────────────┬──────────────────────┐
      │ BLOCK                │ ASK_USER             │ ALLOW
      ▼                      ▼                      ▼
  [Reject Action]     [User CLI Prompt]      [Proceed to Tool]
      │                      │ (Allow / Deny)       │
      │                      ├──────────────────────┤
      │                      │ Denied               │ Allowed
      │                      ▼                      │
      │               [Reject Action]               │
      │                                             ▼
      │                                     7. Tool Execution Boundary
      │                                        - Pre-change snapshot
      │                                        - Atomic file write
      │                                        - Integrity verification
      │                                             │
      ▼                                             ▼
8. Append-Only Audit Ledger <───────────────────────┘
      │
      ▼
9. Feedback to AI Model
```

---

## 4. Security Model & Invariants

1. **Untrusted Model Output**: All LLM outputs are treated as candidate proposals, not approved actions.
2. **LLM Cannot Authorize Itself**: The model has no mechanism to downgrade its own risk score or grant permissions.
3. **Canonical Path Confinement**: `PathGuard` resolves symlinks and canonical paths before evaluation. Paths escaping `workspaceRoot` fail closed.
4. **Fail-Closed Default**: If no explicit policy allows an action, the engine defaults to `BLOCK`.
5. **Protected Sensitive Assets**: Writing or deleting credentials, private keys, or `.env` files is blocked by default (`SEC-003`).
6. **Pre-Change Snapshots**: All modifications record a pre-change snapshot and calculate SHA-256 hashes for atomic rollback.

---

## 5. Current Capabilities (v0.5 — OS Isolation & Network Containment)

- **OS-Level Sandbox Isolation**: Supports `ContainerIsolationProvider` (Docker containers with `--read-only`, `--user node`, `--cap-drop=ALL`, `--network none`), `ProcessIsolationProvider` (OS process groups/Job Objects), and `HostFallbackProvider` (`src/security/isolation/`).
- **Network Containment**: Enforces `NetworkPolicyMode` (`NONE`, `ALLOWLIST`) via `NetworkPolicyValidator`. Mode `NONE` revokes network interfaces in containers and blocks network side effects.
- **Fail-Closed Isolation Selection**: `IsolationFactory` strictly compares required isolation strength against provider capabilities. If container isolation is required but Docker is unavailable, the pipeline **fails closed (`BLOCK`)**.
- **Security Lifecycle State Machine**: Enforces a 12-state fail-closed transition lifecycle (`PROPOSED` → `PARSED` → `POLICY_CHECKED` → `CAPABILITY_GRANTED` → `ISOLATION_PREPARED` → `ISOLATION_VERIFIED` → `PROCESS_STARTED` → `PROCESS_RUNNING` → `PROCESS_TERMINATED` → `EFFECTS_VERIFIED` → `COMPLETED`).
- **Effect Firewall & Impact Intelligence**: Post-execution filesystem, network, and process diffing (`EffectObserver`), 6-rule capability validation (`EffectFirewall`), and blast radius scoring (`ChangeImpactIntelligence`).
- **Diff Engine & AST Verification**: In-memory syntax verification for JS, TS, JSX, TSX, HTML, CSS, JSON (`SyntaxVerifier`), structured diff metrics (`DiffEngine`), and SHA-256 integrity hashing.
- **Tamper-Evident Evidence Ledger**: Append-only cryptographic hash chain recording all state transitions, capability grants, sandbox events, and effect validations (`EvidenceLedger`).
- **TOCTOU Hardening**: Pre-execution `PathGuard` revalidation for all tool operations immediately before execution.

---

## 7. Project Structure

```
CodeGuardian/
├── src/
│   ├── core/               # Types, contracts, errors, EventBus, config
│   ├── security/           # PathGuard, TargetAnalyzer, BlastRadius, RiskEngine
│   ├── permissions/        # PolicyEngine, defaultPolicies, SessionStore
│   ├── tools/              # ListFilesTool, ReadFileTool, WriteFileTool, ToolRegistry
│   ├── verification/       # SnapshotManager, IntegrityVerifier, DiffGenerator
│   ├── audit/              # AuditLogger (append-only JSONL)
│   ├── project/            # WorkspaceContext
│   ├── adapters/           # Host adapter interfaces & CliAdapter
│   ├── models/             # IModelProvider & GeminiProvider
│   ├── agent/              # Governed AgentOrchestrator loop
│   └── index.ts            # Public API exports & CLI entrypoint
├── tests/
│   ├── unit/               # PathGuard, RiskEngine, TargetAnalyzer, Policy, AtomicWriter
│   └── integration/        # End-to-end governed pipeline tests
├── legacy/                 # Preserved original agent.js prototype
├── package.json
└── tsconfig.json
```

---

## 8. Getting Started

### Prerequisites
- Node.js `>= 20.0.0`
- npm `>= 10.0.0`
- Gemini API Key

### Installation

```bash
# Clone or open project directory
cd CodeGuardian

# Install dependencies
npm install

# Configure environment variables
cp .env.example .env
# Edit .env and supply your GEMINI_API_KEY
```

---

## 9. Running CodeGuardian

### Run the Safe Agent CLI

```bash
# Run against the current workspace
npm start

# Or specify a target directory
npm start -- ./some-project
```

### VS Code Extension Packaging (VSIX)

```bash
npm run package
```

---

## 10. Running the Automated Tests

The test suite uses Node's native test runner (`node:test`) combined with `tsx`:

```bash
# Run all unit and integration tests
npm test

# Run unit tests only
npm run test:unit

# Run integration tests only
npm run test:integration
```

---

## 11. Roadmap (v0.1 to v1.0)

| Version | Milestone | Key Deliverables | Status |
| :---: | :--- | :--- | :---: |
| **v0.1** | **Safe Modular Foundation** | PathGuard, RiskEngine, PolicyEngine, Atomic Writer, Snapshot Manager, CLI User Approval, Audit Logger | **COMPLETED** |
| **v0.2** | **Evidence & Verification** | AST Syntax verification, Diff change contracts, Rollback command | **COMPLETED** |
| **v0.3** | **Execution Hardening** | CommandParser, CommandPolicy, ExecutableResolver, NpmScriptAnalyzer, ProcessExecutor | **COMPLETED** |
| **v0.4** | **Effect Firewall** | Filesystem observation, EffectFirewall 6-rule validation, ChangeImpact Intelligence | **COMPLETED** |
| **v0.5** | **OS Isolation & Sandbox** | ContainerIsolationProvider, ProcessIsolationProvider, SecurityStateMachine, NetworkContainment | **COMPLETED** |
| **v0.6** | **Multi-Model Foundation** | Claude, OpenAI, Ollama drivers, DisagreementDetector, VS Code Extension Bridge, Webview Protocol, RegressionGuard | **COMPLETED** |
| **v0.7** | **Functional VS Code Extension** | VS Code extension entrypoint, Security Webview UI panel, approval workflow, VSIX packaging | **COMPLETED** |
| **v1.0** | **Production Release** | Custom policy files, blast radius visualizer, benchmarking suite | *Target* |
