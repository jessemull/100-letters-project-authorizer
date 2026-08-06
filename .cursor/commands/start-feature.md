# Start feature branch (100 Letters Authorizer)

Branch name: **$ARGUMENTS**

If empty, ask for a name (e.g. `feat/scope-check`).

## 1. Load governance

Follow `CONTEXT.md` mandatory reading order before coding.

## 2. Sync and branch

```bash
git fetch origin main
git checkout main
git pull origin main
git checkout -b $ARGUMENTS
```

## 3. Implement

Follow `AGENTS.md` and relevant domain docs. Run `make preflight` before asking to commit/PR.
