package wardn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSystemAssignValidation(t *testing.T) {
	w, clock := newBank(t)
	sys := w.System()
	ctx := context.Background()
	var ue *UndefinedError

	if err := sys.Assign(ctx, "u", "tellr", branch1); !errors.As(err, &ue) || ue.Kind != "role" || ue.Suggestion != "teller" {
		t.Errorf("undefined role: %v", err)
	}
	if err := sys.Assign(ctx, "", "teller", branch1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty user: %v", err)
	}
	if err := sys.Assign(ctx, "u", "teller", NewScope("brnch", "b1")); !errors.As(err, &ue) {
		t.Errorf("undefined scope type: %v", err)
	}

	err := sys.Assign(ctx, "u", "teller", org1)
	if !errors.Is(err, ErrNotAssignable) || !strings.Contains(err.Error(), "assignable at: branch") {
		t.Errorf("assignable_at: %v", err)
	}
	if err := sys.Assign(ctx, "u", "super_admin", org1); !errors.Is(err, ErrNotAssignable) {
		t.Errorf("global-only role at org: %v", err)
	}
	if err := sys.Assign(ctx, "u", "org_admin", Global); !errors.Is(err, ErrNotAssignable) {
		t.Errorf("org-only role at global: %v", err)
	}
	if err := sys.Assign(ctx, "u", "auditor", Global); err != nil {
		t.Errorf("unrestricted role at global: %v", err)
	}

	now := clock.Now()
	if err := sys.Assign(ctx, "u", "teller", branch1, From(now.Add(time.Hour)), Until(now)); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("window ends before start: %v", err)
	}
	if err := sys.Assign(ctx, "u", "teller", branch1, From(now), Until(now)); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty window: %v", err)
	}
	if err := sys.Assign(ctx, "u", "teller", branch1, Until(now)); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("already expired: %v", err)
	}
	if err := sys.Assign(ctx, "u", "teller", branch1, From(now.Add(-time.Hour))); err != nil {
		t.Errorf("start in the past is fine: %v", err)
	}
}

func TestSystemRevoke(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	assign(t, w, "u", "teller", branch1)
	if err := w.System().Revoke(ctx, "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "u", "loan:create", branch1, false)
	if err := w.System().Revoke(ctx, "u", "teller", branch1); err != nil {
		t.Errorf("revoking twice: %v", err)
	}
	if err := w.System().Revoke(ctx, "", "teller", branch1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty user: %v", err)
	}
	if err := w.System().Revoke(ctx, "u", "", branch1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty role: %v", err)
	}
	if err := w.System().Revoke(ctx, "u", "teller", NewScope("nope", "x")); err == nil {
		t.Error("undefined scope type: no error")
	}
}

func TestLinkValidation(t *testing.T) {
	w, _ := newBank(t)
	ctx := context.Background()
	b3, r3 := NewScope("branch", "b3"), NewScope("region", "r3")

	if err := w.Link(ctx, b3, r3); err != nil {
		t.Fatalf("valid link: %v", err)
	}
	for _, tc := range []struct {
		name          string
		child, parent Scope
	}{
		{"skips a level", b3, org1},
		{"wrong direction", r3, b3},
		{"top-level child", org1, region1},
		{"global child", Global, org1},
		{"global parent", region1, Global},
		{"same type", b3, branch1},
	} {
		if err := w.Link(ctx, tc.child, tc.parent); !errors.Is(err, ErrInvalidLink) {
			t.Errorf("%s: err = %v, want ErrInvalidLink", tc.name, err)
		}
	}
	if err := w.Link(ctx, NewScope("brnch", "x"), r3); err == nil {
		t.Error("undefined child type: no error")
	}
	if err := w.Link(ctx, b3, NewScope("region", "")); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("invalid parent ID: %v", err)
	}

	// Relinking moves a branch to another region, and inheritance follows.
	assign(t, w, "pat", "org_admin", org1)
	wantCan(t, w, "pat", "loan:view", branch1, true)
	if err := w.Link(ctx, branch1, region2); err != nil {
		t.Fatal(err)
	}
	wantCan(t, w, "pat", "loan:view", branch1, false)
}

func TestSystemStoreErrors(t *testing.T) {
	fs := &faultyStore{Store: NewMemoryStore()}
	w, _ := newBank(t, func(c *Config) { c.Store = fs })
	ctx := context.Background()
	fs.failAssign, fs.failRevoke, fs.failLink = true, true, true
	if err := w.System().Assign(ctx, "u", "teller", branch1); !errors.Is(err, errStore) {
		t.Errorf("Assign: %v", err)
	}
	if err := w.System().Revoke(ctx, "u", "teller", branch1); !errors.Is(err, errStore) {
		t.Errorf("Revoke: %v", err)
	}
	if err := w.Link(ctx, NewScope("branch", "b9"), region1); !errors.Is(err, errStore) {
		t.Errorf("Link: %v", err)
	}
}

func TestMemoryStore(t *testing.T) {
	m := NewMemoryStore()
	ctx := context.Background()
	a := Assignment{User: "u", Role: "teller", Scope: branch1}
	if err := m.Assign(ctx, a); err != nil {
		t.Fatal(err)
	}
	a.ExpiresAt = t0
	if err := m.Assign(ctx, a); err != nil { // replaces, not duplicates
		t.Fatal(err)
	}
	got, _ := m.Assignments(ctx, "u", []Scope{branch1, Global})
	if len(got) != 1 || !got[0].ExpiresAt.Equal(t0) {
		t.Fatalf("Assignments = %+v", got)
	}
	if got, _ := m.Assignments(ctx, "u", []Scope{branch2}); len(got) != 0 {
		t.Fatalf("other scope returned %+v", got)
	}
	if got, _ := m.Assignments(ctx, "other", []Scope{branch1}); len(got) != 0 {
		t.Fatalf("other user returned %+v", got)
	}
	if err := m.Revoke(ctx, "u", "teller", branch1); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Assignments(ctx, "u", []Scope{branch1}); len(got) != 0 {
		t.Fatalf("after revoke: %+v", got)
	}
	if _, ok, _ := m.Parent(ctx, branch1); ok {
		t.Fatal("unlinked scope has a parent")
	}
	if err := m.Link(ctx, branch1, region1); err != nil {
		t.Fatal(err)
	}
	if p, ok, _ := m.Parent(ctx, branch1); !ok || p != region1 {
		t.Fatalf("Parent = %v, %v", p, ok)
	}
}
