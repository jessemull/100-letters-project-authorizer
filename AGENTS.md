# AGENTS.md — 100 Letters Project Authorizer

> Complete development rules and constraints for AI agents and human contributors.
> This file is the authoritative reference for coding standards. Precedence: see `CONTEXT.md`.

---

## Repository Overview

| Field                 | Value                                                                       |
| --------------------- | --------------------------------------------------------------------------- |
| **Project**           | 100 Letters Project Authorizer                                              |
| **Architecture**      | Single AWS Lambda TOKEN authorizer (API Gateway + Cognito JWT)              |
| **Platform**          | AWS Lambda `nodejs24.x` (us-west-2)                                         |
| **Core Technologies** | TypeScript, `jose`, Webpack 5, Jest, ESLint, CloudFormation                 |
| **CI/CD**             | GitHub Actions → S3 zip → CloudFormation stack                              |
| **Git Hooks**         | Husky + lint-staged + Conventional Commits (commitlint); pre-push preflight |

### Layout

```
100-letters-project-authorizer/
├── src/
│   ├── index.ts           # Lambda handler (JWT verify + IAM policy)
│   └── index.test.ts      # Jest unit tests
├── scripts/
│   ├── cognito-token.js   # Local USER_PASSWORD_AUTH token helper
│   ├── connect.js         # Bastion SSH helper
│   └── preflight.sh       # lint + typecheck + test + build
├── cloudformation/        # S3 bucket + Lambda execution role stacks
├── template.yaml          # Authorizer function + version + invoke permission
├── docs/                  # Governance documentation
├── .cursor/               # Rules, skills, commands
├── .github/workflows/     # PR, merge (dev deploy), deploy, rollback
├── CONTEXT.md
├── AGENTS.md              # This file
└── Makefile
```

### Path aliases

None configured. Prefer shallow relative imports within `src/`. Keep the handler surface small.

---

## Development Commands

Prefer **`make`** targets (see `make help`). Equivalents use npm.

### Setup

| Command           | Description          |
| ----------------- | -------------------- |
| `npm install`     | Install dependencies |
| `npm run prepare` | Install Husky hooks  |

### Quality

| Command          | Description                      |
| ---------------- | -------------------------------- |
| `make lint`      | ESLint with `--fix`              |
| `make typecheck` | `tsc --noEmit`                   |
| `make format`    | Prettier write                   |
| `make test`      | Jest with coverage (≥80%)        |
| `make build`     | Webpack bundle → `dist/index.js` |
| `make package`   | Zip `dist/` → `authorizer.zip`   |
| `make preflight` | lint + typecheck + test + build  |
| `make security`  | `npm audit`                      |

### Local helpers

| Command           | Description                                   |
| ----------------- | --------------------------------------------- |
| `npm run token`   | Cognito access token (needs env — see README) |
| `npm run bastion` | SSH bastion helper                            |

Build injects `COGNITO_USER_POOL_ID` / `COGNITO_USER_POOL_CLIENT_ID` via webpack `DefinePlugin` (from `.env` or CI secrets).

---

## Language and Framework Rules

### TypeScript

- Keep `strict: true`.
- Prefer explicit types on exported APIs; avoid `any`.
- Use `@types/aws-lambda` for authorizer event/result types.

### Lambda handler

- Entry: `export async function handler(...)` in `src/index.ts`.
- TOKEN authorizer contract: read `event.authorizationToken`, return `APIGatewayAuthorizerResult` or throw `"Unauthorized"`.
- Do not change fail-closed auth semantics without human approval.
- Keep Cognito region/issuer construction consistent with the pool region (`us-west-2`).

### Webpack / packaging

- Bundle to CommonJS (`libraryTarget: commonjs2`).
- Do not add Node builtins as bundled deps when they are listed in `externals`.
- `npm run package` zips `dist/` for S3 upload.

---

## Coding Standards

- Match existing formatting (Prettier + ESLint).
- Prefer clear names over comments; when comments are needed, follow `docs/COMMENTS.md`.
- Keep the module surface minimal — this is intentionally a small authorizer.

### Forbidden patterns

- Hardcoded Cognito pool IDs, client IDs, AWS keys, or tokens in source
- Silent allow on verify failure
- Lowering Jest coverage thresholds or deleting tests to pass CI
- Disabling Husky / commitlint / lint-staged without explicit approval
- Adding Next.js, React, LLM SDKs, or unrelated product frameworks without asking
- Committing `.env` or secrets

---

## Testing

See `docs/TESTING.md`. Mock `jose` at the boundary; cover bearer parsing, JWT failure, wrong `token_use`, missing/wrong scope, and success policy/context.

---

## Git

- Conventional Commits only (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`, …).
- Commit only when the user asks.
- Do not push or open PRs unless asked.
- Do not `--no-verify` unless explicitly requested.
