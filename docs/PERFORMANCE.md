# Performance

> **AI agents — read this file when:** changing bundle contents, memory/timeout, or JWKS usage.

---

## Lambda posture

| Setting | Current (`template.yaml`) |
| ------- | ------------------------- |
| Memory  | 128 MB                    |
| Timeout | 5 seconds                 |
| Runtime | nodejs20.x                |

Auth path should stay well under the timeout. Prefer keeping the dependency tree tiny (`jose` only in production deps).

---

## Bundle

- Webpack builds a single `dist/index.js`.
- Avoid adding large AWS SDK clients to the Lambda bundle; keep SDK usage in local `scripts/` unless there is a strong reason.
- Terser drops `console.*` in the minimized bundle — do not rely on production console logging for critical signals without adjusting the minimizer.

---

## JWKS

`createRemoteJWKSet` caches keys in-process. Do not re-create new remote JWKS sets per request in a way that defeats caching without reason.

---

## Cold start

Minimize require graph and avoid dynamic imports of heavyweight modules on the verify path.
