# Dependencies

> **AI agents — read this file when:** adding, removing, or upgrading npm packages.

---

## Principles

- Prefer caret ranges consistent with this repo (`^x.y.z`), except where a tilde/pin is required to stay inside a peer window.
- Keep runtime dependencies minimal (today: `jose` only).
- Put `@types/*` and tooling in `devDependencies`.
- Align Node types with Lambda/CI Node **24** (`@types/node` major **24** — not 26.x).
- Do not add LLM SDKs, UI frameworks, or state libraries without asking.

---

## Upgrade process

1. Audit `package.json` vs latest on npm **and** GitHub Action majors in `.github/workflows/`.
2. Upgrade in coherent groups (runtime → lint/test → bundler → Actions → misc).
3. After each risky group: install, fix breakages, run `make preflight`.
4. Run `make security` / `npm audit`. Record residual risk; **do not** `npm audit fix --force`.
5. Update the **Intentional version holds** table below with real peer/tooling reasons.

Use `.cursor/skills/dependency-upgrade` when performing upgrades.

---

## Intentional version holds

| Package       | Held at   | Latest blocked | Why                                                                             |
| ------------- | --------- | -------------- | ------------------------------------------------------------------------------- |
| `typescript`  | `~6.0.3`  | `>=6.1` / 7.x  | `@typescript-eslint@8` peers `typescript >=4.8.4 <6.1.0` — **6.0.x is allowed** |
| `@types/node` | `^24`     | 26.x           | Lambda + CI are Node **24** (`nodejs24.x`); avoid types for unavailable APIs    |
| `ts-jest`     | `^29.4.x` | (no 30 yet)    | Latest line still 29.x; peers Jest 29/30 and TypeScript `<7`                    |

Notes:

- **`eslint` 10.x** is current (no Next/React a11y peer blockers in this repo).
- **Webpack 6** / **ts-jest 30** do not exist yet as current majors.
- **`lighthouse` / LHCI** holds from other repos do **not** apply here.
- Node.js **24** is the latest AWS Lambda managed runtime (`nodejs24.x`). Handler uses async/await (required — Node 24 Lambda dropped callback-style handlers).

### GitHub Actions (keep current majors)

| Action                                  | Pin  |
| --------------------------------------- | ---- |
| `actions/checkout`                      | `v7` |
| `actions/setup-node`                    | `v7` |
| `actions/upload-artifact`               | `v7` |
| `aws-actions/configure-aws-credentials` | `v6` |

---

## Discouraged without approval

- Additional auth libraries that duplicate `jose` + Cognito JWKS
- SAM CLI / CDK rewrites of the existing CloudFormation path without a migration plan
- Runtime packages that inflate the Lambda bundle without clear need
