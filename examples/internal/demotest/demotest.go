// Package demotest holds test helpers shared by the reference applications.
package demotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MogRex-Limited/wardn/examples/internal/demo"
	"github.com/MogRex-Limited/wardn/wardntest"
)

// Client makes requests to an app as different users.
type Client struct {
	T *testing.T
	H http.Handler
}

// Do sends a request as user ("" for nobody) and returns status and body.
func (c Client) Do(user, method, path, body string) (int, string) {
	c.T.Helper()
	req := httptest.NewRequestWithContext(c.T.Context(), method, path, strings.NewReader(body))
	if user != "" {
		req.Header.Set(demo.UserHeader, user)
	}
	rec := httptest.NewRecorder()
	c.H.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// Want sends a request and fails the test unless it answers status.
func (c Client) Want(user, method, path, body string, status int) string {
	c.T.Helper()
	got, resp := c.Do(user, method, path, body)
	if got != status {
		c.T.Fatalf("%s %s %s: status %d, want %d (%s)", user, method, path, got, status, strings.TrimSpace(resp))
	}
	return resp
}

// AuditAllRoutes fails for any chi route, other than public ones, that does
// not answer 403 to a signed-in user with no roles.
func AuditAllRoutes(t *testing.T, h http.Handler, public ...wardntest.Route) {
	t.Helper()
	param := regexp.MustCompile(`\{[^}]+\}`)
	var routes []wardntest.Route
	err := chi.Walk(h.(chi.Routes), func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, wardntest.Route{Method: method, Path: strings.TrimSuffix(param.ReplaceAllString(pattern, "x"), "/") + suffix(pattern)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wardntest.AuditRoutes(t, h, func(r *http.Request, user string) *http.Request {
		r.Header.Set(demo.UserHeader, user)
		return r
	}, routes, public...)
}

func suffix(pattern string) string {
	if strings.HasSuffix(pattern, "/") && pattern != "/" {
		return "/"
	}
	return ""
}

// GeneratedNamesAreCurrent fails if the app's perm/perm.go is stale.
func GeneratedNamesAreCurrent(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the wardn CLI")
	}
	cmd := exec.CommandContext(context.Background(), "go", "run", "github.com/MogRex-Limited/wardn/cmd/wardn",
		"gen", "-check", "-f", "wardn.yaml", "-o", "perm/perm.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
