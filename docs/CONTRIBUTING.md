# Contributing

> **AI agents — read this file when:** opening PRs, setting up a worktree, or explaining the contributor flow.

---

## Setup

```bash
npm install
cp .env.example .env   # if present; otherwise create .env with Cognito + bastion vars (see README)
make preflight
```

Hooks install via `npm prepare` (Husky). Use `npm run commit` for Commitizen prompts.

---

## Branching and commits

- Prefer branching from `main` for reviewable work; direct-to-`main` only when that is the agreed flow for this repo.
- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`).
- Pre-commit runs lint-staged; commit-msg runs commitlint; pre-push runs `./scripts/preflight.sh`.

---

## Pull requests

1. Keep the change focused; describe What / Why / Testing.
2. Pre-push runs preflight; keep it green before opening the PR.
3. Expect review per `docs/REVIEW.md`.

Governance-only changes: prefix title with `[governance]`.

---

## Code style

- ESLint + Prettier (`make lint` / `make format`).
- Tests for auth behavior changes (`docs/TESTING.md`).

---

## Where to read next

Start at `CONTEXT.md` → `AGENTS.md` → relevant `docs/*`.
