# Testing

> **AI agents — read this file when:** adding or changing tests, adjusting Jest config, or reviewing coverage.

---

## Stack

| Layer       | Tool                                                                                |
| ----------- | ----------------------------------------------------------------------------------- |
| Unit        | Jest + `ts-jest`                                                                    |
| Environment | `node`                                                                              |
| Coverage    | Jest `coverageThreshold` global **≥ 80%** on branches, functions, lines, statements |

Commands: `make test` / `npm test` (coverage on by default via `jest.config.js`). Watch: `npm run test:watch`.

There is no e2e or browser a11y suite in this repo (Lambda-only).

---

## What to test

- Missing / non-Bearer `authorizationToken`
- JWT verify failures (invalid signature, expired, JWKS errors)
- Wrong `token_use` (e.g. `id` instead of `access`)
- Missing or mismatched `client_id` (must match `COGNITO_USER_POOL_CLIENT_ID`)
- Missing or insufficient `scope` (required: `aws.cognito.signin.user.admin`)
- Success path: Allow policy on `event.methodArn`, `principalId`, context fields
- Fail-closed: catch path and missing Bearer throw `Unauthorized`

Mock `jose` (`jwtVerify`, `createRemoteJWKSet`) at the module boundary — do not hit real Cognito in unit tests.

---

## What not to overtest

- Webpack / CloudFormation YAML syntax (covered by CI build/deploy)
- Exact Cognito JWKS HTTP wire format

---

## Policy

- Do **not** lower the 80% thresholds.
- Do **not** delete tests solely to make coverage pass.
- Prefer behavior assertions on the returned policy document and thrown errors.
