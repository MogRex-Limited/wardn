// Package wardn is simple, opinionated authorization for Go.
//
// Products define their own permissions, roles and scope hierarchy in a
// single policy file; wardn stores role assignments, evaluates access on
// every request, protects HTTP routes, and supports admin-created custom
// roles with built-in protection against privilege escalation.
//
// wardn is under active development and has no stable API yet. See
// docs/DESIGN.md for the design and docs/THREAT_MODEL.md for its security
// model.
package wardn
