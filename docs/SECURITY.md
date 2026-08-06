# Security

> **AI agents — read this file when:** handling tokens, env vars, logging, IAM policies, or dependencies.

---

## Secrets and env

- Never commit `.env`, AWS keys, Cognito passwords, or raw JWTs.
- Local: `.env` (gitignored) for `COGNITO_USER_POOL_ID`, `COGNITO_USER_POOL_CLIENT_ID`, bastion vars, token script creds.
- CI: GitHub Actions secrets (`COGNITO_*`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.).
- Webpack `DefinePlugin` inlines pool IDs into the bundle at build time — treat pool IDs as non-secret identifiers, but still do not hardcode them in source; keep them env-driven.

---

## Authorizer surface

- Fail closed: any verification failure → throw `Unauthorized` (deny), including missing Bearer.
- Require Cognito access tokens (`token_use === "access"`) whose `client_id` matches `COGNITO_USER_POOL_CLIENT_ID` (access tokens use `client_id`, not `aud`).
- Do not log full JWTs or passwords. Prefer short error messages (`err.message`) already used in the handler.
- Required scope and `token_use` checks are security controls — changing them needs human review (`docs/GOVERNANCE.md`).
- IAM policy resource should remain scoped to `event.methodArn` unless a deliberate broader policy is approved.
- Fail fast at cold start if `COGNITO_USER_POOL_ID` or `COGNITO_USER_POOL_CLIENT_ID` is missing.

---

## Dependencies

- Run `make security` / `npm audit` after upgrades.
- Do **not** use `npm audit fix --force`.
- Document residual risk in `docs/DEPENDENCIES.md` when CI treats audit as non-blocking.

---

## Scripts

- `scripts/cognito-token.js` and `scripts/connect.js` are local operator tools — never embed production credentials in the repo.
