# TODO

Known gaps, prioritized. Nothing here is broken — these are real features or
hardening steps intentionally left out of the current hardening pass because
they're new work, not a fix to something already built, or because they need
a decision only the team can make.

## Security

- [ ] **Password reset / forgot-password flow.** No endpoint exists today -
      a locked-out or forgetful user has no self-service path back in.
      Needs an OTP-or-link flow similar to registration's, plus a decision
      on whether it invalidates existing refresh tokens (it should).
- [ ] **MFA on login.** OTP exists only for registration verification today.
- [ ] **Refresh-token family/generation-based reuse detection**, per the
      OWASP-recommended pattern. The current model is single-token-per-user
      (delete-and-replace on every rotation), which IP-pinning meaningfully
      backstops but doesn't fully replace - a stolen-and-used token just
      makes the legitimate user's next refresh fail with "not found" rather
      than raising an explicit "reuse detected, revoke everything" signal.
- [ ] **Secrets management.** `jwt.secret`, DB/Redis passwords, and the
      super-admin seed password are all plain environment variables today.
      Fine for a single deploy target; worth moving to Vault/AWS Secrets
      Manager/K8s Secrets + External Secrets Operator once there's more than
      one environment to keep in sync.
- [ ] **Content-Security-Policy header.** Added `Referrer-Policy` in this
      pass; Spring Security's framework defaults cover
      `X-Content-Type-Options`/`X-Frame-Options`/HSTS already, but there's
      still no explicit CSP. Lower priority since this is a JSON API, not an
      HTML-serving app, except for `/swagger-ui.html`.
- [ ] **Tenant existence validation.** `POST /tenants/{tenantId}/users`
      (SUPER_ADMIN) writes the path's `tenantId` straight onto the new user
      without confirming that tenant actually exists in
      tenant-management-service.
- [ ] Consider bumping BCrypt strength from the default (10) to 12 and
      making it configurable via property.

## Architecture

- [ ] **Evaluate moving refresh tokens to Redis with native TTL** instead of
      Postgres + a scheduled cleanup sweep. Redis's own key expiry would
      make `TokenCleanupService`'s refresh-token half unnecessary entirely
      (see its own doc comment for the ShedLock/batching work already done
      as the stopgap). Bigger change - touches `RefreshTokenService`,
      `RefreshTokenRepository`, and the IP-pinning lookup path - not
      something to do casually.
- [ ] Centralized, structured audit-event abstraction. `iiotedge-audit-starter`
      is a dependency and `iiotedge.audit.*` is configured, but nothing in
      this repo's own source confirms what it actually captures for auth
      events specifically - worth confirming with whoever owns that starter
      rather than assuming coverage.
- [ ] Verify the reverse proxy/API gateway actually strips or overwrites
      client-supplied `X-Forwarded-For` before it reaches this service.
      Both `RateLimitAspect` and the refresh-token IP-pinning check
      (`AuthenticationController.resolveClientIp`) trust that header - if
      the edge doesn't sanitize it, both are spoofable.

## Operational

- [ ] **CI pipeline.** No Jenkinsfile or GitHub Actions workflow exists in
      this repo despite `mvn verify`'s full quality gate (tests, coverage,
      SpotBugs) being completely wired up and ready to run in one. It
      currently only runs when someone remembers to run it locally.
- [ ] Automate the OWASP dependency-check CVE scan (the `security-audit`
      Maven profile exists, needs an NVD API key and a few minutes - fine
      for CI, not something to run on every local build).
- [ ] Real DB migrations (Flyway/Liquibase) instead of
      `spring.jpa.hibernate.ddl-auto=update`. Matches the rest of this
      platform's current convention, so not unique to this service, but
      worth a platform-wide look eventually.
- [ ] Validate this service under more than one replica in a real
      environment - ShedLock and batched cleanup (this pass) make that
      believed-safe, but it hasn't been exercised against a real multi-instance
      deployment yet.
