---
name: dependency-upgrade
description: >-
  Upgrade or add npm dependencies safely for the authorizer Lambda.
---

# Dependency Upgrade

Read `docs/DEPENDENCIES.md`.

1. Justify the change; check peers (especially `typescript-eslint`, Jest/`ts-jest`)
2. Install / bump in coherent groups
3. `make preflight`
4. `make security` — never `npm audit fix --force`
5. Update intentional holds table if needed
6. Note breaking changes for the commit/PR
