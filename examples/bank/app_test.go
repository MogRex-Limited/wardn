package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/bank/perm"
	"github.com/MogRex-Limited/wardn/examples/internal/demotest"
	"github.com/MogRex-Limited/wardn/wardntest"
)

var start = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)

// bank is a running bank with the people from the recipe:
//
//	root  platform_admin    (global)
//	ada   org_admin         organisation:acme
//	bisi  branch_manager    branch:lagos
//	bayo  teller            branch:lagos
//	seun  regional_auditor  region:south
type bank struct {
	t     *testing.T
	h     http.Handler
	w     *wardn.Warden
	clock *wardntest.Clock
}

func newBank(t *testing.T) *bank {
	t.Helper()
	policy, err := Policy()
	if err != nil {
		t.Fatal(err)
	}
	clock := wardntest.NewClock(start)
	w := wardntest.NewFromPolicy(t, policy, wardntest.WithClock(clock))
	b := &bank{t: t, h: (&App{w: w, bank: NewBank()}).Router(), w: w, clock: clock}

	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.System().Assign(ctx, "root", perm.RolePlatformAdmin, wardn.Global))
	b.want("root", "POST", "/orgs/acme/regions/south/branches", `{"id":"lagos"}`, http.StatusCreated)
	b.want("root", "POST", "/orgs/acme/regions/south/branches", `{"id":"ibadan"}`, http.StatusCreated)
	b.want("root", "POST", "/orgs/globex/regions/north/branches", `{"id":"abuja"}`, http.StatusCreated)
	must(w.System().Assign(ctx, "ada", perm.RoleOrgAdmin, perm.ScopeOrganisation("acme")))
	must(w.System().Assign(ctx, "seun", perm.RoleRegionalAuditor, perm.ScopeRegion("south")))
	b.want("ada", "PUT", "/branches/lagos/staff/bisi/roles/branch_manager", "", http.StatusNoContent)
	b.want("bisi", "PUT", "/branches/lagos/staff/bayo/roles/teller", "", http.StatusNoContent)
	return b
}

// do makes a request as user and returns the status and body.
func (b *bank) do(user, method, path, body string) (int, string) {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), method, path, strings.NewReader(body))
	if user != "" {
		req.Header.Set("X-User", user)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (b *bank) want(user, method, path, body string, status int) string {
	b.t.Helper()
	got, resp := b.do(user, method, path, body)
	if got != status {
		b.t.Fatalf("%s %s %s: status %d, want %d (%s)", user, method, path, got, status, strings.TrimSpace(resp))
	}
	return resp
}

// newLoan has user create a loan in Lagos and returns its ID.
func (b *bank) newLoan(user string) string {
	b.t.Helper()
	var loan Loan
	if err := json.Unmarshal([]byte(b.want(user, "POST", "/branches/lagos/loans", `{"customer":"c1","amount":5000}`, http.StatusCreated)), &loan); err != nil {
		b.t.Fatal(err)
	}
	return loan.ID
}

func TestHeadOffice(t *testing.T) {
	b := newBank(t)
	loan := b.newLoan("bayo")
	b.want("ada", "POST", "/branches/lagos/loans/"+loan+"/approve", "", http.StatusOK) // inherited from acme
	b.want("ada", "GET", "/regions/south/report", "", http.StatusOK)
	b.want("ada", "GET", "/branches/abuja/loans", "", http.StatusForbidden) // another bank
}

func TestBranchManager(t *testing.T) {
	b := newBank(t)
	b.want("bisi", "GET", "/branches/lagos/loans", "", http.StatusOK)
	b.want("bisi", "GET", "/branches/ibadan/loans", "", http.StatusForbidden) // another branch
	b.want("bisi", "GET", "/regions/south/report", "", http.StatusForbidden)  // no report:export
	b.want("bisi", "GET", "/branches/lagos/members", "", http.StatusOK)

	// The escalation guard: bisi cannot suspend head office (that would
	// need everything "suspended" denies), nor hand out the regional
	// auditor role, which is not assignable at a branch anyway.
	b.want("bisi", "PUT", "/branches/lagos/staff/ada/roles/suspended", "", http.StatusForbidden)
	b.want("bisi", "PUT", "/branches/lagos/staff/x/roles/regional_auditor", "", http.StatusBadRequest)
}

func TestTeller(t *testing.T) {
	b := newBank(t)
	loan := b.newLoan("bayo")
	b.want("bayo", "GET", "/branches/lagos/loans", "", http.StatusOK)
	b.want("bayo", "POST", "/branches/lagos/loans/"+loan+"/approve", "", http.StatusForbidden)
	b.want("bayo", "PUT", "/branches/lagos/staff/x/roles/teller", "", http.StatusForbidden) // no wardn:roles.assign

	var got struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(b.want("bayo", "GET", "/me/branches/lagos/permissions", "", http.StatusOK)), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Permissions, ",") != "customer:view,loan:create,loan:view" {
		t.Errorf("bayo's permissions = %v", got.Permissions)
	}
}

func TestRegionalAuditor(t *testing.T) {
	b := newBank(t)
	b.newLoan("bayo")
	report := b.want("seun", "GET", "/regions/south/report", "", http.StatusOK)
	if !strings.Contains(report, `"loans":1`) {
		t.Errorf("report = %s", report)
	}
	b.want("seun", "GET", "/branches/ibadan/loans", "", http.StatusOK) // every branch in the region
	b.want("seun", "POST", "/branches/lagos/loans", `{"customer":"c","amount":1}`, http.StatusForbidden)
	b.want("seun", "GET", "/regions/north/report", "", http.StatusForbidden)
}

func TestTemporaryApprover(t *testing.T) {
	b := newBank(t)
	// Head office defines the role once, for the whole bank.
	var role wardn.CustomRole
	resp := b.want("ada", "POST", "/orgs/acme/roles",
		`{"name":"Loan Approver","allow":["loan:view","loan:approve"],"assignable_at":["branch"]}`, http.StatusCreated)
	if err := json.Unmarshal([]byte(resp), &role); err != nil {
		t.Fatal(err)
	}

	// The branch manager covers her own leave for one week.
	until := start.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	b.want("bisi", "PUT", "/branches/lagos/staff/tolu/roles/"+role.ID, `{"until":"`+until+`"}`, http.StatusNoContent)

	loan := b.newLoan("bayo")
	b.want("tolu", "POST", "/branches/lagos/loans/"+loan+"/approve", "", http.StatusOK)

	b.clock.Advance(7 * 24 * time.Hour) // a week later, the access is gone by itself
	loan = b.newLoan("bayo")
	b.want("tolu", "POST", "/branches/lagos/loans/"+loan+"/approve", "", http.StatusForbidden)
}

func TestSuspension(t *testing.T) {
	b := newBank(t)
	b.want("ada", "PUT", "/branches/lagos/staff/bayo/roles/suspended", "", http.StatusNoContent)
	b.want("bayo", "POST", "/branches/lagos/loans", `{"customer":"c","amount":1}`, http.StatusForbidden)
	b.want("bisi", "DELETE", "/branches/lagos/staff/bayo/roles/suspended", "", http.StatusForbidden) // only head office lifts it
	b.want("ada", "DELETE", "/branches/lagos/staff/bayo/roles/suspended", "", http.StatusNoContent)
	b.newLoan("bayo") // exactly what he had before
}

func TestMakerChecker(t *testing.T) {
	b := newBank(t)
	loan := b.newLoan("bisi")
	b.want("bisi", "POST", "/branches/lagos/loans/"+loan+"/approve", "", http.StatusForbidden) // business rule, after wardn
}

func TestConfusedDeputy(t *testing.T) {
	b := newBank(t)
	b.want("root", "PUT", "/branches/ibadan/staff/kemi/roles/branch_manager", "", http.StatusNoContent)
	lagosLoan := b.newLoan("bayo")
	// kemi may approve in Ibadan; a Lagos loan through the Ibadan URL is not found.
	b.want("kemi", "POST", "/branches/ibadan/loans/"+lagosLoan+"/approve", "", http.StatusNotFound)
	b.want("kemi", "POST", "/branches/lagos/loans/"+lagosLoan+"/approve", "", http.StatusForbidden)
}

func TestAnonymous(t *testing.T) {
	b := newBank(t)
	b.want("", "GET", "/branches/lagos/loans", "", http.StatusUnauthorized)
	b.want("", "GET", "/me/branches/lagos/permissions", "", http.StatusUnauthorized)
}

// TestEveryRouteIsProtected fails if any route forgets Require.
func TestEveryRouteIsProtected(t *testing.T) {
	demotest.AuditAllRoutes(t, newBank(t).h, wardntest.Route{Method: "GET", Path: "/me/branches/x/permissions"})
}

// TestGeneratedNamesAreCurrent fails if perm/perm.go is stale.
func TestGeneratedNamesAreCurrent(t *testing.T) { demotest.GeneratedNamesAreCurrent(t) }
