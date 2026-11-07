package wardn_test

import (
	"context"
	"fmt"

	"github.com/MogRex-Limited/wardn"
)

const examplePolicy = `
scopes:
  organisation: {}
  branch: { parent: organisation }
permissions:
  customer:view: View customers
  loan:create:   Create loan applications
  loan:approve:  Approve loans
roles:
  org_admin:
    assignable_at: [organisation]
    allow: ["*"]
  teller:
    assignable_at: [branch]
    allow: [customer:view, loan:create]
`

func Example() {
	policy, err := wardn.ParsePolicy([]byte(examplePolicy), "wardn.yaml")
	if err != nil {
		panic(err)
	}
	w := wardn.MustNew(wardn.Config{Policy: policy}) // production: Config{File: "wardn.yaml", Store: ...}
	ctx := context.Background()

	org := wardn.NewScope("organisation", "acme")
	branch := wardn.NewScope("branch", "lagos")
	_ = w.Link(ctx, branch, org) // the Lagos branch belongs to Acme

	_ = w.System().Assign(ctx, "ada", "org_admin", org)
	_ = w.System().Assign(ctx, "bayo", "teller", branch)

	fmt.Println(w.Can(ctx, "ada", "loan:approve", branch))  // inherited from the organisation
	fmt.Println(w.Can(ctx, "bayo", "loan:create", branch))  // teller
	fmt.Println(w.Can(ctx, "bayo", "loan:approve", branch)) // tellers can't approve

	d, _ := w.Check(ctx, "bayo", "loan:approve", branch)
	fmt.Println(d.Reason)
	// Output:
	// true
	// true
	// false
	// no role grants "loan:approve" at branch:lagos
}

func ExampleWarden_Check_typo() {
	policy, _ := wardn.ParsePolicy([]byte(examplePolicy), "wardn.yaml")
	w := wardn.MustNew(wardn.Config{Policy: policy})

	_, err := w.Check(context.Background(), "ada", "loan:aprove", wardn.Global)
	fmt.Println(err)
	// Output:
	// wardn: permission "loan:aprove" is not defined; did you mean "loan:approve"?
}
