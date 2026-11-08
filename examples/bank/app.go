package main

import (
	"cmp"
	_ "embed"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/bank/perm"
	"github.com/MogRex-Limited/wardn/examples/internal/demo"
)

//go:generate go run github.com/MogRex-Limited/wardn/cmd/wardn gen -f wardn.yaml -o perm/perm.go

//go:embed wardn.yaml
var policyFile []byte

// Policy returns the bank's authorization policy.
func Policy() (*wardn.Policy, error) {
	return wardn.ParsePolicy(policyFile, "wardn.yaml")
}

// Branch is a bank branch: the unit staff work in.
type Branch struct {
	ID, Region, Org string
}

// Loan is a loan application at a branch.
type Loan struct {
	ID        string `json:"id"`
	Branch    string `json:"branch"`
	Customer  string `json:"customer"`
	Amount    int    `json:"amount"`
	Status    string `json:"status"`
	CreatedBy string `json:"created_by"`
}

// Bank is the application's own data, kept in memory for the demo.
type Bank struct {
	mu       sync.Mutex
	branches map[string]Branch
	loans    map[string]*Loan
	seq      int
}

// NewBank returns an empty bank.
func NewBank() *Bank {
	return &Bank{branches: map[string]Branch{}, loans: map[string]*Loan{}}
}

// App wires the bank's routes to wardn.
type App struct {
	w    *wardn.Warden
	bank *Bank
}

// Router returns the bank's HTTP API.
func (a *App) Router() http.Handler {
	w := a.w
	r := chi.NewRouter()
	r.Use(demo.Auth)

	// Open to every signed-in user: what may I do in this branch?
	r.Get("/me/branches/{branchID}/permissions", a.myPermissions)

	r.Route("/orgs/{orgID}", func(r chi.Router) {
		r.Use(w.ScopeFrom("organisation", wardn.PathValue("orgID")))
		r.With(w.Require(perm.BranchOpen)).Post("/regions/{regionID}/branches", a.openBranch)
		r.With(w.Require(perm.WardnRolesManage)).Post("/roles", a.createRole)
	})

	r.Route("/regions/{regionID}", func(r chi.Router) {
		r.Use(w.ScopeFrom("region", wardn.PathValue("regionID")))
		r.With(w.Require(perm.ReportExport)).Get("/report", a.regionReport)
	})

	r.Route("/branches/{branchID}", func(r chi.Router) {
		r.Use(w.ScopeFrom("branch", wardn.PathValue("branchID")))
		r.With(w.Require(perm.LoanView)).Get("/loans", a.listLoans)
		r.With(w.Require(perm.LoanCreate)).Post("/loans", a.createLoan)
		r.With(w.Require(perm.LoanApprove)).Post("/loans/{loanID}/approve", a.approveLoan)
		r.With(w.Require(perm.WardnRolesAssign)).Get("/members", a.members)
		r.With(w.Require(perm.WardnRolesAssign)).Put("/staff/{userID}/roles/{role}", a.assign)
		r.With(w.Require(perm.WardnRolesAssign)).Delete("/staff/{userID}/roles/{role}", a.revoke)
	})
	return r
}

// openBranch records a branch and links it into the hierarchy, so roles
// at its region and organisation apply in it.
func (a *App) openBranch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := demo.Decode(w, r, &body); err != nil || body.ID == "" {
		demo.Error(w, demo.ErrBadBody)
		return
	}
	org, region := r.PathValue("orgID"), r.PathValue("regionID")
	ctx := r.Context()
	if err := a.w.Link(ctx, perm.ScopeRegion(region), perm.ScopeOrganisation(org)); err != nil {
		demo.Error(w, err)
		return
	}
	if err := a.w.Link(ctx, perm.ScopeBranch(body.ID), perm.ScopeRegion(region)); err != nil {
		demo.Error(w, err)
		return
	}
	a.bank.mu.Lock()
	a.bank.branches[body.ID] = Branch{ID: body.ID, Region: region, Org: org}
	a.bank.mu.Unlock()
	demo.JSON(w, http.StatusCreated, map[string]string{"branch": body.ID, "region": region, "organisation": org})
}

func (a *App) createLoan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Customer string `json:"customer"`
		Amount   int    `json:"amount"`
	}
	if err := demo.Decode(w, r, &body); err != nil || body.Amount <= 0 {
		demo.Error(w, demo.ErrBadBody)
		return
	}
	a.bank.mu.Lock()
	a.bank.seq++
	loan := &Loan{ID: strconv.Itoa(a.bank.seq), Branch: r.PathValue("branchID"), Customer: body.Customer,
		Amount: body.Amount, Status: "pending", CreatedBy: demo.User(r)}
	a.bank.loans[loan.ID] = loan
	a.bank.mu.Unlock()
	demo.JSON(w, http.StatusCreated, loan)
}

func (a *App) listLoans(w http.ResponseWriter, r *http.Request) {
	branch := r.PathValue("branchID")
	a.bank.mu.Lock()
	out := []Loan{}
	for _, l := range a.bank.loans {
		if l.Branch == branch {
			out = append(out, *l)
		}
	}
	a.bank.mu.Unlock()
	slices.SortFunc(out, func(x, y Loan) int { return cmp.Compare(seqOf(x.ID), seqOf(y.ID)) })
	demo.JSON(w, http.StatusOK, out)
}

// seqOf returns a loan ID's sequence number (IDs are generated in order).
func seqOf(id string) int {
	n, _ := strconv.Atoi(id)
	return n
}

// errOwnLoan is a business rule wardn does not express: nobody approves a
// loan they created (maker-checker).
var errOwnLoan = errors.New("you cannot approve a loan you created")

func (a *App) approveLoan(w http.ResponseWriter, r *http.Request) {
	a.bank.mu.Lock()
	defer a.bank.mu.Unlock()
	loan := a.bank.loans[r.PathValue("loanID")]
	// The confused-deputy check: wardn checked the branch in the URL, so the
	// loan must belong to that branch. Otherwise answer as if it did not
	// exist, so other branches' loan IDs cannot be probed.
	if loan == nil || loan.Branch != r.PathValue("branchID") {
		demo.Error(w, demo.ErrNotFound)
		return
	}
	if loan.CreatedBy == demo.User(r) {
		demo.JSON(w, http.StatusForbidden, map[string]string{"error": errOwnLoan.Error()})
		return
	}
	loan.Status = "approved"
	demo.JSON(w, http.StatusOK, loan)
}

func (a *App) regionReport(w http.ResponseWriter, r *http.Request) {
	region := r.PathValue("regionID")
	a.bank.mu.Lock()
	defer a.bank.mu.Unlock()
	count, total := 0, 0
	for _, l := range a.bank.loans {
		if a.bank.branches[l.Branch].Region == region {
			count++
			total += l.Amount
		}
	}
	demo.JSON(w, http.StatusOK, map[string]any{"region": region, "loans": count, "total_amount": total})
}

// assign gives a staff member a role in this branch, on behalf of the
// signed-in user. wardn's escalation guard decides whether they may.
func (a *App) assign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Until time.Time `json:"until"`
	}
	if r.ContentLength > 0 {
		if err := demo.Decode(w, r, &body); err != nil {
			demo.Error(w, err)
			return
		}
	}
	var opts []wardn.AssignOption
	if !body.Until.IsZero() {
		opts = append(opts, wardn.Until(body.Until))
	}
	branch := perm.ScopeBranch(r.PathValue("branchID"))
	if err := a.w.Assign(r.Context(), r.PathValue("userID"), r.PathValue("role"), branch, opts...); err != nil {
		demo.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) revoke(w http.ResponseWriter, r *http.Request) {
	branch := perm.ScopeBranch(r.PathValue("branchID"))
	if err := a.w.Revoke(r.Context(), r.PathValue("userID"), r.PathValue("role"), branch); err != nil {
		demo.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) members(w http.ResponseWriter, r *http.Request) {
	page, next, err := a.w.Members(r.Context(), perm.ScopeBranch(r.PathValue("branchID")), r.URL.Query().Get("cursor"), 50)
	if err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusOK, map[string]any{"members": page, "next": next})
}

// createRole lets head office define a custom role for the whole bank.
func (a *App) createRole(w http.ResponseWriter, r *http.Request) {
	var spec wardn.RoleSpec
	if err := demo.Decode(w, r, &spec); err != nil {
		demo.Error(w, err)
		return
	}
	role, err := a.w.CreateRole(r.Context(), perm.ScopeOrganisation(r.PathValue("orgID")), spec)
	if err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusCreated, role)
}

func (a *App) myPermissions(w http.ResponseWriter, r *http.Request) {
	user := demo.User(r)
	if user == "" {
		demo.Error(w, wardn.ErrUnauthenticated)
		return
	}
	perms, err := a.w.PermissionsOf(r.Context(), user, perm.ScopeBranch(r.PathValue("branchID")))
	if err != nil {
		demo.Error(w, err)
		return
	}
	demo.JSON(w, http.StatusOK, map[string]any{"permissions": perms})
}
