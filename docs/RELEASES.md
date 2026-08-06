# Releases

> **AI agents — read this file when:** shipping, versioning, or documenting deploy/rollback.

---

## How this repo ships

1. **Build** — Webpack bundles `src/index.ts` → `dist/index.js` (Cognito env injected at build).
2. **Package** — `npm run package` zips `dist/` → `dist/authorizer.zip`.
3. **Upload** — CI copies the zip to `s3://100-letters-project-authorizer-{env}/authorizer/{version-hash-ts}.zip`.
4. **Deploy** — CloudFormation stack `one-hundred-letters-authorizer-stack-{env}` updates the Lambda code via `S3Key` + `Environment`.

Environments: **dev** and **prod**.

---

## Triggers

| Path                             | Effect                                          |
| -------------------------------- | ----------------------------------------------- |
| Pull request → `main`            | Lint, test (≥80%), build/package (no deploy)    |
| Push / merge → `main`            | Lint, test, build, deploy **dev**               |
| `deploy.yml` workflow_dispatch   | Manual deploy to **dev** or **prod**            |
| `rollback.yml` workflow_dispatch | Redeploy a prior S3 artifact via CloudFormation |

---

## Versioning

- `package.json` `version` is included in artifact names.
- Prefer Conventional Commits; bump version deliberately when cutting meaningful releases.
- Lambda versions are created via `AWS::Lambda::Version` in `template.yaml`.

---

## Rollback checklist

1. Identify a known-good S3 object key under `authorizer/`.
2. Run the rollback workflow with that key and target environment.
3. Verify API Gateway authorizer behavior with a valid and an invalid token.

---

## Agent rules

- Do not push or deploy unless the user asks.
- Do not change stack names, bucket naming, or region without human review.
