package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/MogRex-Limited/wardn"
	"github.com/MogRex-Limited/wardn/examples/internal/demotest"
	"github.com/MogRex-Limited/wardn/examples/school/perm"
)

// newSchool returns two schools:
//
//	head   principal of s1   (classes c1, c2)
//	other  principal of s2
//	tim    teacher of c1;  amy and ben students of c1
type school struct {
	demotest.Client
	w    *wardn.Warden
	data *Data
}

func newSchool(t *testing.T) *school {
	t.Helper()
	policy, err := Policy()
	if err != nil {
		t.Fatal(err)
	}
	data := NewData()
	w, err := wardn.New(wardn.Config{Policy: policy, ParentOf: data.ParentOf})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for user, s := range map[string]string{"head": "s1", "other": "s2"} {
		if err := w.System().Assign(ctx, user, perm.RolePrincipal, perm.ScopeSchool(s)); err != nil {
			t.Fatal(err)
		}
	}
	s := &school{Client: demotest.Client{T: t, H: (&App{w: w, data: data}).Router()}, w: w, data: data}
	s.Want("head", "POST", "/schools/s1/classes", `{"id":"c1"}`, http.StatusCreated)
	s.Want("head", "POST", "/schools/s1/classes", `{"id":"c2"}`, http.StatusCreated)
	s.Want("head", "PUT", "/classes/c1/teachers/tim", "", http.StatusNoContent)
	s.Want("head", "PUT", "/classes/c1/students/amy", "", http.StatusNoContent)
	s.Want("head", "PUT", "/classes/c1/students/ben", "", http.StatusNoContent)
	return s
}

func (s *school) grades(user, class string) []grade {
	s.T.Helper()
	var out []grade
	if err := json.Unmarshal([]byte(s.Want(user, "GET", "/classes/"+class+"/grades", "", http.StatusOK)), &out); err != nil {
		s.T.Fatal(err)
	}
	return out
}

// TestPrincipalInheritsThroughParentOf: the principal's school role reaches
// every class, though wardn stores nothing about which class is where.
func TestPrincipalInheritsThroughParentOf(t *testing.T) {
	s := newSchool(t)
	s.Want("head", "PUT", "/classes/c1/grades/amy", `{"grade":"A"}`, http.StatusNoContent)
	s.Want("head", "PUT", "/classes/c2/grades/zed", `{"grade":"B"}`, http.StatusNoContent)
	s.Want("other", "GET", "/classes/c1/grades", "", http.StatusForbidden)
}

func TestTeacher(t *testing.T) {
	s := newSchool(t)
	s.Want("tim", "PUT", "/classes/c1/grades/amy", `{"grade":"A"}`, http.StatusNoContent)
	s.Want("tim", "PUT", "/classes/c1/grades/ben", `{"grade":"C"}`, http.StatusNoContent)
	if got := s.grades("tim", "c1"); len(got) != 2 {
		t.Fatalf("teacher sees %v, want every grade", got)
	}
	s.Want("tim", "PUT", "/classes/c2/grades/x", `{"grade":"A"}`, http.StatusForbidden) // not his class
	s.Want("tim", "PUT", "/classes/c1/students/eve", "", http.StatusForbidden)          // can't enrol
}

// TestStudentsSeeOnlyTheirOwnGrades: a business rule on top of wardn.
func TestStudentsSeeOnlyTheirOwnGrades(t *testing.T) {
	s := newSchool(t)
	s.Want("tim", "PUT", "/classes/c1/grades/amy", `{"grade":"A"}`, http.StatusNoContent)
	s.Want("tim", "PUT", "/classes/c1/grades/ben", `{"grade":"C"}`, http.StatusNoContent)
	got := s.grades("amy", "c1")
	if len(got) != 1 || got[0].Student != "amy" {
		t.Fatalf("amy sees %v, want only her own grade", got)
	}
	s.Want("amy", "PUT", "/classes/c1/grades/amy", `{"grade":"A+"}`, http.StatusForbidden)
	s.Want("amy", "GET", "/classes/c2/grades", "", http.StatusForbidden)
}

// TestMovingAClassMovesAccess: ParentOf reads live data, so moving a class
// to another school changes who may act in it on the next request.
func TestMovingAClassMovesAccess(t *testing.T) {
	s := newSchool(t)
	s.Want("head", "GET", "/classes/c1/grades", "", http.StatusOK)
	s.data.MoveClass("c1", "s2")
	s.Want("head", "GET", "/classes/c1/grades", "", http.StatusForbidden)
	s.Want("other", "GET", "/classes/c1/grades", "", http.StatusOK)
	s.Want("tim", "GET", "/classes/c1/grades", "", http.StatusOK) // class-level roles move with the class
}

func TestLinkIsDisabledWithParentOf(t *testing.T) {
	s := newSchool(t)
	err := s.w.Link(t.Context(), perm.ScopeClass("c1"), perm.ScopeSchool("s2"))
	if !errors.Is(err, wardn.ErrLinksExternal) {
		t.Fatalf("Link with ParentOf: %v", err)
	}
}

func TestEveryRouteIsProtected(t *testing.T) {
	demotest.AuditAllRoutes(t, newSchool(t).H)
}

func TestGeneratedNamesAreCurrent(t *testing.T) { demotest.GeneratedNamesAreCurrent(t) }
