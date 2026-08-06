# CONTEXT.md — 100 Letters Project Authorizer

> **This is the PRIMARY entry point for ALL AI agents working in this repository.**
> Read this file first. Follow the mandatory reading order below before making any changes.

---

## Mandatory Reading Order

Every agent MUST read the following documents **in order** before making any change:

1. **`CONTEXT.md`** (this file) — loading order, source-of-truth precedence, non-negotiable constraints, quality gates
2. **`AGENTS.md`** — complete development rules, architecture constraints, coding standards, and forbidden patterns
3. **`docs/GOVERNANCE.md`** — contribution workflow, PR process, review policy, release process
4. **`docs/ARCHITECTURE.md`** — system design, folder structure, data flow
5. **`docs/TESTING.md`** — testing strategy, coverage requirements
6. **`docs/COMMENTS.md`** — comment policy and documentation standards
7. **`docs/SECURITY.md`** — security policy, secret management
8. **`docs/DEPENDENCIES.md`** — dependency management
9. **`docs/RELEASES.md`** — release and deploy process
10. **`docs/CI_CD.md`** — CI workflows and quality gates

Read items 5–10 on every task. Do not skip them because the work "seems unrelated"; agents cannot know upfront which rules will apply.

Domain docs to load when the task touches that area: `docs/ERROR_HANDLING.md`, `docs/NETWORKING.md`, `docs/PERFORMANCE.md`.

For PR or repo reviews, also read **`docs/REVIEW.md`**.

---

## Source-of-Truth Precedence

When instructions conflict, the **higher-ranked source wins**:

| Priority    | Source                               | Scope                                         |
| ----------- | ------------------------------------ | --------------------------------------------- |
| 1 (highest) | `CONTEXT.md`                         | Repository-wide constraints and quality gates |
| 2           | `docs/GOVERNANCE.md`                 | Contribution workflow and review policy       |
| 3           | `docs/ARCHITECTURE.md`               | System design and module boundaries           |
| 4           | Domain docs (`ERROR_HANDLING`, etc.) | Domain-specific rules                         |
| 5 (lowest)  | Inline code comments                 | Local implementation notes                    |

**Lower-precedence instructions MUST NOT contradict higher-precedence instructions.** If a conflict is detected, flag it for human review and follow the higher-precedence source.

---

## Non-Negotiable Constraints

These constraints apply to **every change**. No exceptions without explicit human approval.

### Platform and runtime

- **AWS Lambda TOKEN authorizer** for API Gateway — handler is `index.handler` (bundled from `src/index.ts`).
- **Runtime `nodejs24.x`** — keep local Node, CI (`setup-node`), and `template.yaml` aligned on Node 24.
- **Webpack to zip to S3 to CloudFormation** deploy path — do not assume SAM CLI or container images.

### Auth behavior

- Validate **Cognito access** JWTs via JWKS (`jose`); require `token_use === "access"` and scope `aws.cognito.signin.user.admin`.
- Fail closed: invalid/missing auth must result in API Gateway deny (`Unauthorized`), never a silent allow.
- Do not hardcode Cognito pool IDs or secrets — env / CI secrets / webpack `DefinePlugin` only.

### Type safety and quality

- **TypeScript `strict: true`** — do not weaken compiler options.
- **No blanket `any`** — prefer typed `aws-lambda` / `jose` payloads; narrow assertions only when justified.
- **≥ 80% Jest coverage** (branches, functions, lines, statements) — do not lower the threshold; do not delete tests to greenwash coverage.
- **Conventional Commits** — enforced by commitlint + Husky.

### Secrets and boundaries

- **No hardcoded secrets** — `.env` is local-only (gitignored); CI uses GitHub Actions secrets.
- Do **not** add LLM SDKs, heavy UI kits, or unrelated product features without asking.

---

## Quality Gates

Before considering work complete, agents MUST ensure:

| Gate                  | Command                                     |
| --------------------- | ------------------------------------------- |
| Lint (auto-fix)       | `make lint` / `npm run lint`                |
| Typecheck             | `make typecheck` / `npm run typecheck`      |
| Format                | `make format` / `npm run format`            |
| Unit tests + coverage | `make test` / `npm test`                    |
| Production build      | `make build` / `npm run build`              |
| Full preflight        | `make preflight` / `./scripts/preflight.sh` |

CI also runs lint, Jest (≥80%), and webpack package on PRs; merge to `main` deploys **dev**. See `docs/CI_CD.md`.

---

## Repository Identity

| Field             | Value                                                             |
| ----------------- | ----------------------------------------------------------------- |
| **Name**          | 100 Letters Project Authorizer (`one-hundred-letters-authorizer`) |
| **Role**          | Cognito JWT authorizer Lambda for the 100 Letters Project API     |
| **Stack**         | TypeScript, Webpack 5, Jest, ESLint, CloudFormation               |
| **Sibling repos** | API, Next.js client, Lambda@Edge (see README)                     |
