# Governance

> **Precedence:** CONTEXT.md > **GOVERNANCE.md** > ARCHITECTURE.md > domain docs > inline comments.
>
> **AI agents — read this file when:** making structural decisions, resolving conflicting guidance, determining what requires human review, or changing governance docs.

---

## Source-of-truth precedence

| Rank | Document          | Scope                                   |
| ---- | ----------------- | --------------------------------------- |
| 1    | `CONTEXT.md`      | Constraints and quality gates           |
| 2    | `GOVERNANCE.md`   | Process and authority                   |
| 3    | `ARCHITECTURE.md` | Structure and boundaries                |
| 4    | Domain docs       | Error handling, networking, performance |
| 5    | Inline comments   | Local intent                            |

Resolve conflicts upward, never downward.

---

## Non-negotiable constraints

- Lambda runtime stays `nodejs20.x` unless a coordinated platform upgrade is approved.
- TypeScript strict mode; ≥ 80% Jest coverage.
- Conventional Commits + Husky hooks must remain enabled.
- No hardcoded secrets; Cognito IDs only via env / CI / webpack DefinePlugin.
- Authorizer must fail closed (deny on invalid/missing auth).

---

## Decision authority

### Autonomous (no extra human gate beyond normal PR)

- Bug fixes that do not change auth semantics or deploy topology
- Tests and documentation within existing files
- Lint/format fixes
- Internal refactors that preserve the handler contract and IAM policy shape

### Requires human review

- Changes to JWT validation rules (issuer, algorithms, `token_use`, required scopes)
- Changes to governance docs (`CONTEXT.md`, `AGENTS.md`, `docs/*`)
- New third-party dependencies
- CI/CD or CloudFormation / `template.yaml` changes
- Security-sensitive code (token logging, env handling, policy resource ARNs)
- Removing tests or lowering coverage thresholds
- Runtime major upgrades (e.g. Node 20 → 22)

### Requires explicit product decision

- Changing which Cognito scopes or token types are accepted
- Expanding this Lambda beyond TOKEN authorizer responsibilities
- New AWS regions or multi-pool auth

---

## Governance doc change process

1. Open a PR with `[governance]` in the title (or commit on `main` when that is the agreed flow).
2. Explain why, prior guidance, and impact.
3. Cascade updates to lower-ranked docs in the same change set when needed.

---

## Review policy

- Use severity tiers in `docs/REVIEW.md` (MUST / SHOULD / NICE).
- MUST items block merge.
- Agents using `.cursor/skills/pr-review` or `repo-review` must follow that output shape.
