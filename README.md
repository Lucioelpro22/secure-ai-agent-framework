# Secure AI Agent Framework

Small, auditable building blocks for AI-assisted workflows that must remain under human control.

This project is a **security-oriented framework baseline**, not an autonomous operator. It helps an application describe an agent's policy, expose narrowly scoped tools, require approval for consequential actions, and retain an auditable record of what was proposed and executed.

## Security posture

The default posture is deliberately conservative:

- **Read-only by default.** A tool must explicitly declare any side effect.
- **Deny by default.** Unknown tools, capabilities, recipients, and resources are rejected.
- **Human approval for consequential actions.** The application—not the model—decides whether approval is needed and who may grant it.
- **Fail closed.** Missing policy, expired approval, malformed arguments, budget exhaustion, or unavailable audit storage stops execution.
- **Bounded execution.** Timeouts, step limits, tool budgets, payload limits, and cancellation are part of the execution contract.
- **Complete audit trail.** Intent, policy decision, approval, invocation, result metadata, and failure are recorded without storing secrets by default.
- **No hidden autonomy.** The framework does not loop indefinitely, escalate privileges, invent credentials, bypass controls, or send messages without an explicit tool and policy decision.

This baseline does not make an LLM trustworthy by itself. Treat model output as untrusted input and keep credentials, policy evaluation, and side effects outside the model.

## What it provides

- Typed agent requests and execution decisions.
- Declarative policies for tools, capabilities, resources, recipients, and budgets.
- A tool registry with input validation and explicit side-effect metadata.
- Human approval tokens bound to one action, policy version, identity, and expiry.
- Redacted structured audit events suitable for a durable append-only sink.
- Deterministic offline execution for tests and local development.
- Extension points for model providers and application-specific tool adapters.

The framework intentionally does **not** provide unrestricted shell access, browser automation, credential management, sandbox escape mechanisms, or a production authorization service.

## Quick start

The public API is intentionally small. A typical integration follows this shape (names may evolve while the API is stabilized):

```python
from secure_ai_agent_framework import (
    AgentPolicy,
    ApprovalMode,
    ToolSpec,
    SecureAgent,
)


policy = AgentPolicy(
    allowed_tools={"lookup_ticket"},
    approval_mode=ApprovalMode.CONSEQUENTIAL,
    max_steps=4,
    max_tool_calls=4,
)

lookup_ticket = ToolSpec(
    name="lookup_ticket",
    description="Read one ticket by its opaque identifier",
    side_effects=False,
    allowed_resources={"tickets:read"},
)

agent = SecureAgent(policy=policy, tools=[lookup_ticket])
result = agent.run("Summarize ticket T-104 for the support lead")
print(result.status)
```

For a write operation, declare it as a write and require approval in the application:

```python
create_draft = ToolSpec(
    name="create_draft",
    description="Create an unsent draft; never sends it",
    side_effects=True,
    approval=ApprovalMode.ALWAYS,
    allowed_resources={"mail:drafts:create"},
)

# The framework returns a pending-approval decision. The application presents
# the exact action to an authorized human and resumes only with a short-lived,
# action-bound approval token.
```

Never place API keys, refresh tokens, private prompts, or unredacted personal data in a model prompt or an audit event. Pass opaque references to tools and resolve sensitive values inside a trusted adapter.

## Tool design rules

Every tool adapter should:

1. Have one narrow purpose and a typed input schema.
2. Declare read/write/destructive behavior, resource scope, recipient scope, and timeout.
3. Validate authorization again at execution time; do not trust model-generated claims.
4. Use idempotency keys for writes and an explicit dry-run mode where possible.
5. Return bounded, structured output with secret and personal-data redaction.
6. Avoid generic `exec`, arbitrary URLs, unrestricted filesystem paths, and dynamic code evaluation.

For high-impact actions—deleting data, changing permissions, sending external messages, publishing content, moving money, or operating safety-critical systems—use a separate approval workflow and an independent policy service.

## Repository layout

```text
src/secure_ai_agent_framework/  # policy, tools, approvals, audit, orchestration
tests/                          # deterministic unit and safety tests
docs/                           # architecture, threat model, and safe-use guidance
examples/                       # intentionally inert integration examples
```

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
python -m ruff check .
python -m mypy src
```

Run examples only with local fixtures. Do not point them at production accounts or paste production credentials into environment files.

## Scope and limitations

This is an engineering baseline and reference implementation. It is not a certification, a substitute for a threat model, or a guarantee against prompt injection, compromised dependencies, malicious tools, model errors, or operator mistakes. Production deployments need isolated execution, secret-manager integration, identity-aware authorization, durable audit storage, monitoring, incident response, and independent review.

See [SECURITY.md](SECURITY.md), [docs/safe-use.md](docs/safe-use.md), and [docs/threat-model.md](docs/threat-model.md) before connecting tools.

## License

Released under the MIT License. See [LICENSE](LICENSE).
