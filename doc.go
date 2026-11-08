// Package wardn is simple, opinionated authorization for Go.
//
// Products define their own permissions, roles and scope hierarchy in a
// single policy file; wardn stores role assignments, evaluates access on
// every request, protects HTTP routes, and supports admin-created custom
// roles with built-in protection against privilege escalation.
//
// wardn has no stable API until v1.0.0. From then on it follows the
// compatibility promise in docs/STABILITY.md. See docs/DESIGN.md for the
// design and docs/THREAT_MODEL.md for its security model.
package wardn
