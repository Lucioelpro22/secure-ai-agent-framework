# Secure AI Agent Framework — Architecture

## Purpose

Secure AI Agent Framework is a defensive reference implementation for building
tool-using agents with explicit permissions, deterministic policy decisions,
auditability, and human approval. It is designed to make unsafe capabilities
hard to expose accidentally; it is not an autonomous operator and it must not
be used to bypass access controls or execute unreviewed high-impact actions.

## Design principles

1. **Deny by default.** An agent has no tool, network, filesystem, or data
   access until a policy grants it for a specific task.
2. **Least privilege and narrow scope.** Permissions are bound to an agent,
   task, resource, operation, and expiration time.
3. **Plan before effect.** The model may propose a plan, but an executor only
   performs an action after policy evaluation and, where required, explicit
   human approval.
4. **Fail closed.** Invalid policy, ambiguous target, expired approval,
   unavailable audit sink, or uncertain authorization blocks the action.
5. **Evidence over claims.** Every decision records the policy version, input
   hashes, tool identity, and result classification without storing secrets or
   unnecessary user content.
6. **Reversibility first.** Read-only and preview operations are preferred;
   irreversible operations are either prohibited or require a separate,
   time-bound approval.

## Component model

```text
User / reviewer
      │ request + approval
      ▼
Task API ──► Orchestrator ──► Policy Engine ──► Approval Service
                 │                   │                │
                 │                   └── decision ────┘
                 ▼
           Tool Gateway ──► Sandboxed Tool Adapter ──► External system
                 │
                 ▼
             Audit Ledger
```

### Core components

- **Task API:** accepts a task description, declared target, requested
  capabilities, and data classification. It assigns a unique task ID and
  rejects ambiguous or unbounded scopes.
- **Orchestrator:** turns the task into a structured plan. It may use an LLM
  for interpretation, but the model cannot call tools directly or alter the
  policy decision.
- **Policy engine:** evaluates each planned action against capability,
  resource, actor, environment, risk, and expiry constraints. It returns an
  immutable `ALLOW`, `REQUIRE_APPROVAL`, or `DENY` decision with reasons.
- **Approval service:** binds approval to the exact task, action digest,
  target, policy version, approver identity, and expiry. A changed plan
  invalidates the approval.
- **Tool gateway:** the only path to tools. It validates arguments, enforces
  timeouts and quotas, strips credentials from logs, and prevents undeclared
  network/filesystem access.
- **Sandboxed adapters:** small, typed adapters for individual providers. An
  adapter exposes a capability such as `repo.read` rather than arbitrary
  shell execution or an unrestricted SDK client.
- **Audit ledger:** append-only security events, preferably write-once or
  externally protected. It records decisions and outcomes, not prompts,
  tokens, secrets, or full sensitive payloads.

## Domain model

The reference types should remain serializable and versioned:

```text
Task
  id, requester, purpose, target, data_classification,
  requested_capabilities, created_at, expires_at

Action
  id, task_id, capability, operation, target, arguments_digest,
  risk_class, reversibility, proposed_by

PolicyDecision
  decision, reason_codes, policy_version, action_digest,
  obligations, evaluated_at, expires_at

Approval
  approval_id, action_digest, approver, method, scope,
  approved_at, expires_at, status

AuditEvent
  event_id, task_id, action_id, actor, event_type, outcome,
  input_digest, timestamp, correlation_id
```

Raw credentials, access tokens, complete prompts, and unredacted tool output
must never be fields in persisted domain objects. Store only a redacted
summary and a cryptographic digest when correlation is needed.

## Permission and risk model

Capabilities are positive grants, not broad roles. Examples:

| Capability | Default | Typical risk | Example constraint |
| --- | --- | --- | --- |
| `repo.read` | deny | low | named repository, branch, 10-minute TTL |
| `repo.metadata` | deny | low | named repository only |
| `repo.write.preview` | deny | medium | diff generation only, no mutation |
| `repo.write` | deny | high | prohibited in baseline; separate reviewed profile |
| `ticket.create` | deny | medium | named project, human approval |
| `network.fetch` | deny | medium | allowlisted HTTPS hosts, GET only |
| `shell.exec` | prohibited | critical | not exposed by the framework |
| `credential.read` | prohibited | critical | never available to the model |

Risk is the maximum of operation risk, data sensitivity, target sensitivity,
and environmental risk. `critical` actions are denied by the baseline. A
policy may lower neither the operation's inherent risk nor a provider's
boundary; it can only narrow scope further.

## Request lifecycle

1. Authenticate requester and create a bounded `Task`.
2. Classify data and resolve the target to an unambiguous resource ID.
3. Generate a structured plan with typed actions; never execute free-form
   model output.
4. Evaluate each action independently. Unknown, malformed, expired, or
   contradictory inputs produce `DENY`.
5. For `REQUIRE_APPROVAL`, render a human-readable diff containing target,
   exact operation, inputs, side effects, expiry, and rollback information.
6. Verify approval immediately before execution, then issue a one-use,
   short-lived execution token bound to the action digest.
7. Execute through the gateway with quotas, timeout, cancellation, and output
   redaction.
8. Record decision, approval, start, completion, and failure events. Return a
   minimal result plus an audit reference.

Retries must use a new idempotency key and must not silently broaden scope.
Cancellation prevents new actions but cannot guarantee rollback of an action
already accepted by an external provider.

## Policy rules

Policies should be versioned, code-reviewed, and validated before activation.
At minimum they must support:

- capability and operation allowlists;
- exact or pattern-constrained resource scope;
- actor, environment, and tenant conditions;
- data-classification ceilings;
- rate, time, and concurrency limits;
- approval thresholds and separation of duties;
- explicit deny rules that override allows;
- expiry and emergency revocation.

Suppression or exception rules require an owner, justification, ticket, expiry,
and audit event. There is no permanent global bypass.

## Trust boundaries

The LLM is untrusted input and is separated from credentials, policy storage,
the audit ledger, and direct network access. Tool output is also untrusted:
it may contain prompt-injection text, misleading instructions, or sensitive
data. Adapters return typed results and the orchestrator treats returned text
as data, never as policy or executable instructions.

## Availability and operational controls

- Per-task timeout, token budget, tool-call limit, and response-size limit.
- Circuit breakers for repeated provider failures.
- Correlation IDs without putting secrets in IDs or logs.
- Clock checks for TTL and approval expiry, with a conservative failure mode.
- Health checks that distinguish policy/audit failure from provider failure.
- Emergency kill switch that blocks new executions and is itself audited.

The baseline implementation should provide deterministic offline tests for
policy evaluation, approval binding, scope validation, redaction, replay,
expiry, and fail-closed behavior.
