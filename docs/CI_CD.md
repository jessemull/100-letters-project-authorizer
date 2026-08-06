# CI / CD

> **AI agents — read this file when:** changing workflows, gates, or local parity with CI.

---

## Workflows

| Workflow     | File                                 | Trigger             | Role                                      |
| ------------ | ------------------------------------ | ------------------- | ----------------------------------------- |
| Pull Request | `.github/workflows/pull-request.yml` | PR → `main`         | Build/package, lint, Jest + coverage ≥80% |
| Merge        | `.github/workflows/merge.yml`        | Push → `main`       | Lint/test → build → S3 → CFN **dev**      |
| Deploy       | `.github/workflows/deploy.yml`       | `workflow_dispatch` | Manual deploy **dev** / **prod**          |
| Rollback     | `.github/workflows/rollback.yml`     | `workflow_dispatch` | Redeploy prior zip                        |

Region: **us-west-2**. Node: **20**.

---

## Blocking PR gates

- `npm run lint`
- `npm test` (Jest coverage thresholds in `jest.config.js` + CI HTML threshold check)
- `npm run build` + `npm run package` (needs Cognito pool secrets for DefinePlugin)

There is no separate typecheck job yet — local `make preflight` includes `tsc --noEmit`. Prefer keeping that green before push (Husky pre-push).

---

## Local parity

| CI              | Local                                               |
| --------------- | --------------------------------------------------- |
| lint            | `make lint`                                         |
| test + coverage | `make test`                                         |
| build           | `make build` (needs Cognito env in `.env` or shell) |
| full gate       | `make preflight`                                    |

---

## Secrets used by CI

- `COGNITO_USER_POOL_ID_DEV` / `COGNITO_USER_POOL_CLIENT_ID_DEV` (and prod equivalents on deploy)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`

Do not print secret values in logs or commit them.

---

## Out of scope for agents

- Changing GitHub org branch protection settings
- Rotating AWS or Cognito credentials
