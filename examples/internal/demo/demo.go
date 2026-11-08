// Package demo holds the small pieces the reference applications share.
// None of it is part of wardn.
package demo

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/MogRex-Limited/wardn"
)

// UserHeader is the header the demo apps read the user from.
const UserHeader = "X-User"

// Auth trusts the X-User header and puts the user in the request context.
//
// DEMO ONLY. Anyone can send any header. A real application verifies a
// session or token here, then calls wardn.WithUser with the verified ID.
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := r.Header.Get(UserHeader); user != "" {
			r = r.WithContext(wardn.WithUser(r.Context(), user))
		}
		next.ServeHTTP(w, r)
	})
}

// User returns the signed-in user.
func User(r *http.Request) string {
	u, _ := wardn.UserOf(r.Context())
	return u
}

// JSON writes v as JSON with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writing response", "err", err)
	}
}

// ErrBadBody reports a request body that is not the expected JSON.
var ErrBadBody = errors.New("bad request body")

// ErrNotFound reports a record that does not exist.
var ErrNotFound = errors.New("not found")

// Error answers with the right status for err and a generic message that
// reveals nothing. wardn's errors map through wardn.HTTPStatus.
func Error(w http.ResponseWriter, err error) {
	status := wardn.HTTPStatus(err)
	switch {
	case errors.Is(err, ErrBadBody):
		status = http.StatusBadRequest
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	}
	if status == http.StatusInternalServerError {
		slog.Error("request failed", "err", err)
	}
	JSON(w, status, map[string]string{"error": http.StatusText(status)})
}

// Decode reads a small JSON body into v.
func Decode(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrBadBody
	}
	return nil
}

// AuditLog returns a wardn OnChange hook that logs every change, as a
// product's audit trail would. A real product writes to durable storage
// and returns an error if it cannot, which stops the change.
func AuditLog(log *slog.Logger) func(context.Context, wardn.Event) error {
	return func(_ context.Context, e wardn.Event) error {
		log.Info("audit", "event", e.Type, "actor", e.Actor, "system", e.System,
			"user", e.User, "role", e.Role, "scope", e.Scope.String(), "failed", e.Err != nil)
		return nil
	}
}
