# Networking

> **AI agents — read this file when:** changing JWKS URL construction, Cognito region, or outbound calls.

---

## Runtime outbound calls

The Lambda reaches Cognito JWKS over HTTPS:

`https://cognito-idp.us-west-2.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json`

- Built via `jose` `createRemoteJWKSet`.
- Issuer must match the same pool URL prefix.
- Region is currently **us-west-2** — changing region requires coordinated pool + code + docs updates.

No other outbound HTTP should be added to the hot path without review (cold start + failure modes).

---

## Local tooling

- `scripts/cognito-token.js` — Cognito `USER_PASSWORD_AUTH` against the user pool (operator machine).
- `scripts/connect.js` — SSH to bastion (operator machine).

These are not invoked by the Lambda.
