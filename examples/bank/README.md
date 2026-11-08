# Multi-branch bank

A lending platform for several banks. Each bank (an *organisation*) has regions, and each region has branches. This is the [Multi-branch bank recipe](../../website/src/content/docs/recipes/bank.mdx) as a running application.

```bash
cd examples
go run ./bank
```

Try it (the demo trusts the `X-User` header; see the examples README):

```bash
# root is the platform admin. Open a branch in Acme's South region:
curl -X POST localhost:8080/orgs/acme/regions/south/branches -H 'X-User: root' -d '{"id":"lagos"}'

# Make bayo a teller in Lagos:
curl -X PUT localhost:8080/branches/lagos/staff/bayo/roles/teller -H 'X-User: root'

# bayo creates a loan, but cannot approve it:
curl -X POST localhost:8080/branches/lagos/loans -H 'X-User: bayo' -d '{"customer":"c1","amount":5000}'
curl -X POST localhost:8080/branches/lagos/loans/1/approve -H 'X-User: bayo'     # 403

# What may bayo do here?
curl localhost:8080/me/branches/lagos/permissions -H 'X-User: bayo'
```

`app_test.go` walks through every scenario in the recipe: head office, branch managers, tellers, regional auditors, a temporary approver, a suspension, and the confused-deputy check.
