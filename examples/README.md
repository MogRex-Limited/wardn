# Reference applications

Four small applications that use wardn the way product teams will, through its public API only. Their tests prove that the behaviour the documentation describes really happens.

| App | Shows |
|---|---|
| [`bank`](bank) | Organisations › regions › branches; tellers, managers, auditors; custom roles; temporary approvers; suspensions; the confused-deputy check |
| [`saas`](saas) | Workspaces and projects; customer-defined roles; object-level access through project scopes; sign-up with `System()` |
| [`simple`](simple) | No tenancy at all: global roles only |
| [`school`](school) | Hierarchy resolved from the app's own data with `ParentOf`; a business rule ("students see only their own grades") on top of wardn |

Run one (SQLite, no setup):

```bash
cd examples
go run ./bank            # listens on :8080; see the app's README for requests to try
```

Run every app's tests:

```bash
cd examples && go test ./...
```

> **Demo authentication.** These apps trust an `X-User` header so you can try them with `curl`. Never do that in production: put the user ID in the context from your real authentication (`wardn.WithUser`).
