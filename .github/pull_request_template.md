## What and why

<!-- What does this change do, and why is it needed? Link the issue or design section. -->

## Security checklist

<!-- Tick each item, or explain why it does not apply. Reviewers verify these. -->

- [ ] Every new error path **fails closed** (results in deny).
- [ ] Tests prove the new behaviour, including a test that would **fail if a protection were removed**.
- [ ] Threats this change mitigates have tests named `TestThreat_<ID>_...`.
- [ ] New attack surface (inputs, APIs, storage, hooks) is covered in `docs/THREAT_MODEL.md`.
- [ ] All external input is validated: IDs, names, permissions, sizes.
- [ ] No new direct dependency, **or** it is allowlisted with a justification in `.github/allowed-dependencies.txt`.
- [ ] No `//nolint` without a specific linter and an explanation.
- [ ] Public API changes are reflected in `docs/DESIGN.md`.

## How it was tested

<!-- Commands run, scenarios covered, anything reviewers should try. -->
