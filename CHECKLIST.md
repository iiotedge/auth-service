# Production Readiness Checklist

What's actually verified vs. still open, as of this hardening pass. See
`TODO.md` for the detail and reasoning behind each unchecked item.

## Authentication & authorization

- [x] Passwords hashed with BCrypt, never logged or returned
- [x] No hardcoded credentials in source (seeded super-admin password is a
      required env var in prod, dev-only fallback in `application-dev.yml`)
- [x] JWT signing secret required with no insecure fallback in prod
      (previously defaulted to the same value as the public dev secret)
- [x] Refresh tokens are opaque, server-side, rotated on every use, IP-pinned
- [x] Refresh-token reuse detection via token families - a replayed,
      already-rotated-away token or an IP mismatch revokes the whole
      family, not just the one token
- [x] Password-reset flow, enumeration-safe, revokes all sessions on reset
- [x] Change-password for an already-authenticated user (`/change-password`,
      distinct from the forgot-password reset flow above) - verifies the
      current password, same session-revocation hygiene as reset
- [x] `GET /me` - authenticated caller can fetch their own profile without
      needing admin-panel access to another endpoint
- [x] Login MFA, opt-in per account (OTP-based - see `TODO.md` re: TOTP)
- [x] RBAC enforced via Spring Security method security
      (`@PreAuthorize`/`@RolesAllowed`), not just controller-level checks
- [x] Tenant-ownership checked explicitly wherever a path carries a `tenantId`
- [ ] Secrets sourced from a vault/secrets manager rather than plain env vars

## Abuse & brute-force protection

- [x] Rate limiting on `/login`, `/register`, `/register/verify`,
      `/otp/resend`, `/password-reset/*`, `/mfa/verify`
- [x] Account lockout after repeated failed login attempts, configurable
      threshold and duration
- [x] OTP guess attempts capped, independent of the resend budget - shared
      across registration, password-reset, and login-MFA OTPs
- [x] OTP resend budget enforced and reads its configured limit (previously
      hardcoded, ignoring the config value)

## Configuration & secrets

- [x] No profile ships a real credential as a silently-reused fallback
      across environments (dev's local-only fallbacks are intentional and
      documented; prod requires its own explicit values)
- [x] `.gitignore` excludes local logs, OS files, and `.env*`
- [ ] Secrets sourced from a vault/secrets manager rather than plain env vars

## Data lifecycle

- [x] Expired login-history rows and refresh tokens are swept on a schedule
- [x] Scheduled cleanup is safe under multiple replicas (ShedLock) - a naive
      `@Scheduled` job would otherwise run redundantly on every instance
- [x] Cleanup work is batched and capped per run, so a large backlog can't
      turn one sweep into one long-running transaction
- [ ] Real DB migrations (Flyway/Liquibase) instead of `ddl-auto: update`

## Testing & static analysis

- [x] Unit test suite covers controllers, services, security, repositories
- [x] JaCoCo coverage gate enforced (≥85% instruction, ≥65% branch) and met
- [x] SpotBugs + FindSecBugs clean, with a documented (not blanket) baseline
      for the two remaining accepted findings
- [ ] Integration tests against a real Spring context / test database
      (current suite is Mockito-based unit tests only)
- [ ] Load/performance testing

## Observability

- [x] `/actuator/prometheus` exposed with JVM + custom metrics
- [x] Logging never includes passwords, tokens, or full request/response
      payloads (fixed `LoggingAspect`, which both never fired due to a
      stale package reference *and* would have logged credentials once fixed)
- [ ] Distributed tracing
- [ ] Alerting rules for lockouts, rate-limit hits, cleanup-job failures

## Deployment

- [x] CI workflow exists (`.github/workflows/ci.yml`, `mvn verify` on every
      PR/push to `main`) - **but needs a `PLATFORM_REPO_TOKEN` secret
      configured and its first live run watched**; only verified via a
      local simulation of the checkout layout, not a real runner
- [ ] The multi-repo checkout `ci.yml` relies on is a stopgap - the real
      fix is publishing the parent POM chain + `common` modules to GitHub
      Packages (see `TODO.md`)
- [ ] OWASP dependency-check CVE scan automated (profile exists, not
      scheduled anywhere)
- [ ] Verified running with more than one replica in a real environment
