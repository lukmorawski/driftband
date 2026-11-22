## What changed

## Security checklist (see SECURITY-TESTING.md)

- [ ] New/changed API routes have a `securityMatrix` entry (role, audit action, tenant scoping)
- [ ] Every state change writes an audit entry; refused permission checks use `a.deny`
- [ ] Feature-specific security rules have their own test
- [ ] `scripts/security-tests.sh` passes
