# Secure AI Agent Framework — Roadmap

The roadmap is ordered by safety dependency. Later capabilities must not be
enabled by weakening the baseline deny-by-default behavior.

## v0.1 — Defensive core

- [ ] Typed task, action, capability, decision, approval, and audit models.
- [ ] Deterministic policy engine with explicit deny precedence.
- [ ] In-memory/offline tool gateway with quotas and timeout enforcement.
- [ ] Human approval binding to an action digest and expiry.
- [ ] Redacted append-only audit events.
- [ ] CLI or API for plan, evaluate, approve, and dry-run flows.
- [ ] Unit/property tests for fail-closed and replay behavior.

## v0.2 — Sandboxed adapters

- [ ] Read-only repository and HTTP adapters with strict allowlists.
- [ ] Typed provider errors, cancellation, idempotency, and bounded output.
- [ ] Egress proxy and redirect/private-address protections.
- [ ] Secret injection only inside adapters; no credential values in model
      context or persisted task state.
- [ ] Threat-model-driven integration tests with synthetic fixtures.

## v0.3 — Operational assurance

- [ ] Signed/versioned policies and protected policy review workflow.
- [ ] Durable tamper-evident audit storage and retention controls.
- [ ] Separation of duties, emergency revocation, and global kill switch.
- [ ] Metrics for denials, approvals, tool failures, latency, and budget use.
- [ ] CI gates for dependency audit, CodeQL, type checks, coverage, and SBOM.

## v0.4 — Controlled write workflows

- [ ] Preview/diff support for narrowly scoped reversible changes.
- [ ] Explicit rollback metadata and provider capability declarations.
- [ ] Two-person approval for high-impact changes.
- [ ] Post-execution verification and automatic stop on invariant violation.
- [ ] External red-team review before enabling any production write adapter.

## v1.0 — Production reference profile

- [ ] Versioned compatibility contract for policies and adapters.
- [ ] Multi-tenant isolation and disaster-recovery exercises.
- [ ] Formal review of critical invariants and independent security audit.
- [ ] Published safe-use guide, operator runbooks, and incident procedures.
- [ ] A documented list of capabilities intentionally not supported.

## Explicit non-goals

The project will not provide unrestricted shell execution, autonomous credential
handling, stealth/persistence features, exploit delivery, mass unsolicited
messaging, or an “auto-approve” mode. Any future capability that could create
material harm requires a new threat model and explicit human governance.
