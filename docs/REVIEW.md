# PR Review Framework

> **Precedence:** CONTEXT.md > GOVERNANCE.md > ARCHITECTURE.md > **REVIEW.md**.
>
> **AI agents — read this file when:** reviewing a PR, writing review comments, or deciding merge blockers.

---

## Severity tiers

### MUST (blocking)

- Auth regressions (silent allow, weakened scope/`token_use` checks, wrong issuer/algorithms)
- Security issues (hardcoded secrets, logging full JWTs/passwords)
- Crash bugs on the authorizer happy/deny paths
- Coverage threshold regressions or deleted tests without replacement
- Type-safety abuse (`any` sprawl without justification)
- Breaking the Lambda handler contract (`index.handler`, TOKEN event shape) without a migration plan

### SHOULD (significant)

- Missing tests for behavior changes
- Bundle size / cold-start footguns (unnecessary runtime deps)
- IAM policy resource broader than `event.methodArn` without justification
- CI/workflow drift from documented gates
- Incomplete error handling vs `docs/ERROR_HANDLING.md`

### NICE TO HAVE (non-blocking)

- Naming polish
- Optional refactors of equivalent approaches
- Extra docs polish

---

## PR hygiene

- [ ] Focused change; Conventional Commits
- [ ] `make preflight` contemplated / CI green
- [ ] No unrelated drive-by edits
- [ ] No secrets committed

---

## Domain checklists (internal — do not paste wholesale into review output)

### Authorizer / Cognito

- Bearer parsing; JWKS verify; access token + required scope
- Fail closed to `Unauthorized`

### Packaging / infra

- Webpack externals and Node 24 runtime still aligned
- CloudFormation / template changes reviewed for env and S3 key params

### Security

- No secrets in source; careful logging

### CI / craftsmanship fail signals

- Silent `catch` that allows
- Disabled lint/hooks to "make it pass"
- Magic Cognito IDs in source

---

## Agent review output

Skills `pr-review` and `repo-review` define the fixed section output shape. Use this file for severity definitions only; do not dump checklist tables into the user-facing review.
