# Security Policy

## Supported versions

Until the first stable release, security fixes are provided for the latest commit on `main` and the latest published release. Pin a release or commit in deployments; do not depend on an unreviewed moving branch.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private security advisory process for this repository. If that channel is unavailable, contact the repository maintainer privately with:

- affected version or commit;
- minimal reproduction or proof of concept;
- impact and required privileges;
- logs that are sanitized of tokens, personal data, and customer content.

We will acknowledge a report, reproduce it in an isolated environment, assess severity, and coordinate a fix or mitigation. Please allow reasonable time for a fix before public disclosure.

## Security boundaries

This project treats model output, tool output, retrieved documents, and user-provided text as untrusted. A prompt cannot grant a capability, approve an action, alter policy, or reveal a secret. Only a trusted application identity and policy path can do that.

The framework is intentionally not a sandbox. Do not register a tool that exposes unrestricted shell commands, arbitrary network access, arbitrary filesystem paths, or credential export. Run side-effecting adapters in an isolated, least-privileged worker with egress restrictions.

## Deployment requirements

Before production use:

- pin and scan dependencies and container images;
- use a secret manager and short-lived credentials;
- isolate workers and apply network egress allowlists;
- enforce per-tool and per-resource authorization outside the model;
- require fresh, action-bound human approval for consequential writes;
- make audit storage append-only and protect it from the agent identity;
- configure timeouts, cancellation, quotas, and a kill switch;
- redact secrets and personal data before logs leave the trust boundary;
- test prompt injection, confused deputy, replay, SSRF, data exfiltration, and approval bypass scenarios.

## Known non-goals

The framework does not guarantee model correctness, detect every malicious instruction, replace identity governance, or make a dangerous tool safe merely by registering it. A safe deployment depends on the adapters, credentials, infrastructure, policies, and operational controls surrounding this package.
