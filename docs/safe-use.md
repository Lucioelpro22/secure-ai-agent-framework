# Safe-use guide

## The intended operating model

Keep the model in the proposal layer and keep authority in the application:

```text
request -> model proposes plan -> policy validates -> human approves (if required)
        -> trusted adapter executes one bounded action -> redacted audit event
```

The model may suggest a tool and arguments. It must not decide that a tool exists, expand its own permissions, approve its own action, or choose a new recipient outside policy.

## Recommended policy tiers

| Tier | Examples | Default treatment |
| --- | --- | --- |
| Read-only | Fetch a ticket, calculate a report, inspect a fixture | Allow only scoped resources; log input and result metadata |
| Reversible write | Create a draft, add a label, open a review item | Require approval and idempotency; show exact diff |
| External or destructive | Send a message, delete data, change permissions, publish | Separate approval, explicit target, short expiry, strong identity, and post-action review |

Never use a lower tier merely because a tool name sounds harmless. Classify the real effect of the adapter.

## Approval checklist

An approval screen should show the exact tool, normalized arguments, target resources, recipient, expected side effect, estimated cost, policy version, and expiry. Approvals should be:

- bound to a single action hash;
- bound to the approving identity and tenant;
- short-lived and single-use;
- invalidated if arguments, policy, model plan, or target changes;
- recorded before execution.

Do not accept a free-form “yes” from the model, a stale approval, or an approval copied from another request.

## Prompt-injection defenses

Treat retrieved pages, emails, documents, and tool responses as data, not instructions. Keep them in a separate typed field, strip active content, cap their size, and require the model to cite the source of a proposed action. The policy engine must run after planning and before every side effect.

## Safe example

An agent can inspect a local fixture and prepare an unsent draft. It cannot send the draft, access arbitrary mailboxes, or use a token supplied in document content. The user reviews the exact recipient and body; only then does a trusted mail adapter create the draft under a scoped identity.

## Unsafe example

Do not expose `run_shell(command: str)`, `fetch_url(url: str)`, or `send_email(to: str, body: str)` without strict schemas, resource allowlists, authorization, approval, network controls, and audit. A generic tool turns a prompt-injection bug into a system compromise.

## Incident response

If an agent behaves unexpectedly: revoke its credentials, disable side-effecting tools, preserve redacted audit events, identify the policy and model versions, inspect downstream systems, and rotate any exposed secrets. Do not resume execution until the root cause and blast radius are understood.

## Parameter snapshots and token lifetime

`ActionRequest` copies its parameters into immutable nested mappings and tuples.
Parameters must use finite JSON values and string keys; recursive values and
non-JSON objects are rejected. Approval digests cover the subject, action,
resource, operation, and every nested parameter. Object key order does not
change a digest; array order does. Changing a recipient, body, or other argument
requires a new request and approval.

After authorization, pass `request.to_arguments()` to your trusted execution
adapter, or use the frozen `request.parameters` with `ToolRequest`. Do not return
to the mutable dictionary that was originally used to construct the request.
Approval tokens authenticate their identity, subject, digest, issue time, and
expiry, with a positive lifetime of at most one hour. Timestamps must include a
timezone. Previously issued tokens using the older signature scheme must be
reissued after upgrading.

Single use is atomic across threads sharing one `ApprovalAuthority`. Replay
state is in memory: keep that instance alive for the lifetime of its key. This
implementation does not coordinate separate processes or survive a restart.
Use a durable atomic replay store in a production adapter before sharing a
signing key across workers, or rotate the key when the authority restarts. The
application must separately bind the approving human, tenant, and policy
version; `subject` identifies the requesting agent.
