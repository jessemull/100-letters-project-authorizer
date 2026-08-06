# Error Handling

> **AI agents — read this file when:** changing try/catch paths or API Gateway deny behavior.

---

## Authorizer contract

API Gateway TOKEN authorizers treat a thrown error with message **`Unauthorized`** as deny. Other thrown messages may surface differently; keep the public failure path consistent:

1. Input validation failures (missing Bearer) may throw early.
2. JWT / claims failures are caught, logged briefly, and rethrown as `new Error("Unauthorized")`.

Do not return an explicit Deny policy document unless deliberately changing the authorizer style with human approval — this codebase uses the throw-`Unauthorized` pattern.

---

## Logging

- Log `err.message` (or equivalent short reason), not the raw token.
- Avoid logging full payloads that may include PII from Cognito claims beyond what is required for debugging.

---

## Scripts

Local scripts (`cognito-token`, bastion) should fail with clear stderr messages and non-zero exit codes; they are not part of the Lambda runtime path.
