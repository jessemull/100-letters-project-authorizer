---
name: push-validation
description: >-
  Validate the tree is safe to push: preflight and secret hygiene.
---

# Push Validation

1. Ensure no `.env` or secrets staged
2. Run `make preflight`
3. Confirm branch tracking / ahead-behind vs `origin/main`
4. Push only if the user asked
