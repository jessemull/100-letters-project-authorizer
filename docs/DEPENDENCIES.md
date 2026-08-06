# Dependencies

> **AI agents — read this file when:** adding, removing, or upgrading npm packages.

---

## Principles

- Prefer caret ranges consistent with this repo (`^x.y.z`).
- Keep runtime dependencies minimal (today: `jose` only).
- Put `@types/*` and tooling in `devDependencies`.
- Align Node types with Lambda/CI Node **20** (`@types/node` major 20 or 22 — not bleeding-edge majors that document APIs unavailable on 20).
- Do not add LLM SDKs, UI frameworks, or state libraries without asking.

---

## Upgrade process

1. Audit `package.json` vs latest on npm.
2. Upgrade in coherent groups (runtime → lint/test → bundler → misc).
3. After each risky group: install, fix breakages, run `make preflight`.
4. Run `make security` / `npm audit`. Record residual risk; **do not** `npm audit fix --force`.
5. Update the **Intentional version holds** table below with real peer/tooling reasons.

Use `.cursor/skills/dependency-upgrade` when performing upgrades.

---

## Intentional version holds

| Package       | Held at          | Latest blocked | Why                                                           |
| ------------- | ---------------- | -------------- | ------------------------------------------------------------- |
| `typescript`  | `^5.x`           | 6.x / 7.x      | `@typescript-eslint` peers `typescript >=4.8.4 <6.1.0`        |
| `@types/node` | `^22` (or `^20`) | 26.x           | Lambda + CI are Node **20**; avoid types for unavailable APIs |

`eslint` **10.x** is allowed in this repo (no `eslint-config-next` / React a11y plugins). Re-validate peers after major bumps.

`lighthouse` / LHCI holds from other repos do **not** apply here.

---

## Discouraged without approval

- Additional auth libraries that duplicate `jose` + Cognito JWKS
- SAM CLI / CDK rewrites of the existing CloudFormation path without a migration plan
- Runtime packages that inflate the Lambda bundle without clear need
