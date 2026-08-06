---
name: debugging
description: >-
  Debug authorizer failures (Unauthorized, JWKS, scope, packaging).
---

# Debugging

1. Reproduce with unit tests mocking `jose` when possible
2. Check Bearer parsing, issuer, `token_use`, scope
3. For deploy issues: artifact S3 key, CFN params, runtime Node 24, env injection at build
4. Prefer adding a failing test before fixing
