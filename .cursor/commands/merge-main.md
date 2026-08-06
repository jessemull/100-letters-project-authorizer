# Update branch from main (100 Letters Authorizer)

```bash
git fetch origin main
git merge origin/main
# or: git rebase origin/main  (only if user explicitly wants rebase)
make preflight
```

Resolve conflicts respecting architecture and security docs. Do not force-push unless explicitly requested.
