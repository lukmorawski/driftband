# Security Policy

## Reporting a vulnerability

Please report security issues privately to **lmorawski@driftband.app**, or via
GitHub's private vulnerability reporting ("Report a vulnerability" on the
repository's Security tab). Please do not open a public issue for security
problems.

Include steps to reproduce and the affected version/commit. You can expect an
acknowledgement within a few days.

## Scope notes

- Driftband sends ICMP echo requests to the hosts you configure. Only point it
  at hosts you are authorized to probe. The author accepts no responsibility
  for misuse or hostile use of the software, in particular for probing
  networks the operator does not own or administer (see "Responsible use" in
  the README).
- Driftband has built-in accounts, roles, 2FA and an audit log. Serve it over
  HTTPS behind a reverse proxy and set `TRUSTED_PROXIES` to match it (see
  [SECURITY-TESTING.md](SECURITY-TESTING.md)).
- The container runs as a non-root user with no Linux capabilities, a
  read-only root filesystem and `no-new-privileges`; published images carry
  SBOM and provenance attestations.
- Security regressions are guarded by an automated test suite; see
  [SECURITY-TESTING.md](SECURITY-TESTING.md).
