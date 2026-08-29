# CodeGuardian Changelog

## [0.7.0] - 2026-08-29

### Added
- **Functional VS Code Extension**: Integrated CodeGuardian's governed AI security pipeline into VS Code via `codeguardian.openPanel`.
- **VS Code Extension Manifest**: Added publisher metadata, activation events, command contributions (`codeguardian.start`, `audit`, `rollback`, `openPanel`, `showEvidence`), and VSIX packaging script.
- **Interactive Security Webview UI**: Request input box, security dashboard, multi-model status, action proposal cards, diff viewer, explicit approval controls (`ASK_USER`), regression test tracker, rollback controls, and cryptographic evidence chain.
- **Extended Webview RPC Protocol**: `PING`, `START`, `AUDIT`, `SUBMIT_PROPOSAL`, `APPROVE`, `REJECT`, `ROLLBACK`, `GET_STATE`, `GET_DIFF`, `GET_EVIDENCE`, and `SELECT_MODEL` commands with runtime schema validation.
- **VSIX Packaging**: Configured `.vscodeignore` and `vsce package` script to generate `codeguardian-0.7.0.vsix`.

### Security
- Preserved all v0.5/v0.6 security invariants (PathGuard, RiskEngine, PolicyEngine, CapabilityManager, IsolationFactory, EffectFirewall, RegressionGuard, EvidenceLedger).
- Verified zero direct OS execution from VS Code extension host.
- Verified automatic secret redaction (`[REDACTED_SECRET]`) across Webview UI state updates.
