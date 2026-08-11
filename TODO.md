# TODO

Known gaps, prioritized. Nothing here is broken — these are real features or
hardening steps intentionally left out, either because they're new work
rather than a fix to something already built, or because they need a
decision only the team can make.

## Resolved (kept here briefly for context, not action items)

- ~~Refresh-token reuse detection~~ — done. Token rotation now uses a
  `familyId` + `revoked` flag (not delete-and-replace); presenting an
  already-revoked token or a mismatched IP revokes the whole family.
- ~~Password-reset flow~~ — done (`/password-reset/init` + `/confirm`),
  enumeration-safe, revokes all sessions on success.
- ~~MFA on login~~ — done, but OTP-based rather than TOTP (see below).
- ~~No CI pipeline~~ — `.github/workflows/ci.yml` added, but see its own
  header comment and the entry below - it's a stopgap, not the real fix.
- ~~Deprecated Spring Boot 3.4.2 properties in all three profiles~~ —
  `spring.redis.*` -> `spring.data.redis.*` (including `RedisConfig.java`'s
  `@Value` lookups and the now-also-deprecated boolean `ssl` ->
  `ssl.enabled`), and `management.metrics.export.prometheus.enabled` ->
  `management.prometheus.metrics.export.enabled` /
  `management.endpoint.prometheus.access: unrestricted` (Boot 3.4 replaced
  the per-endpoint `enabled` boolean with an `access` level). Verified
  against the actual `spring-configuration-metadata.json` bundled in the
  3.4.2 jars, not guessed; 185/185 tests still pass.

## Architecture

- [ ] **Publish the parent POM chain + `common` modules to GitHub
      Packages**, matching tenant-management-service's already-adopted
      pattern. This is the actual fix for CI/standalone-buildability -
      the multi-repo-checkout workaround in `ci.yml` exists specifically
      because `auth-service/pom.xml` still resolves its parent via local
      relative paths (`com.iotmining:microservices` ->
      `com.iotmining:iotmining-technology`) and its
      `iiotedge-audit-starter`/`com.iotmining.common:data`/`:base`
      dependencies are built from source in a separate `common` repo,
      never published anywhere. This is a platform-wide decision, not
      something fixable from within auth-service alone.
- [ ] **Evaluate moving refresh tokens to Redis with native TTL** instead
      of Postgres + a scheduled cleanup sweep. Redis's own key expiry
      would make `TokenCleanupService`'s refresh-token half unnecessary
      entirely. Bigger change - touches `RefreshTokenService`,
      `RefreshTokenRepository`, and the IP-pinning/family-revocation
      lookups - not something to do casually, and the family/reuse-detection
      model added in this pass would need to be re-thought for Redis's
      simpler key-value shape (no easy "revoke everything with this
      familyId" bulk operation the way SQL's `UPDATE ... WHERE` gives you).
- [ ] Centralized, structured audit-event abstraction. `iiotedge-audit-starter`
      is a dependency and `iiotedge.audit.*` is configured, but nothing in
      this repo's own source confirms what it actually captures for auth
      events specifically - worth confirming with whoever owns that
      starter rather than assuming coverage.
- [ ] Verify the reverse proxy/API gateway actually strips or overwrites
      client-supplied `X-Forwarded-For` before it reaches this service.
      Both `RateLimitAspect` and the refresh-token IP-pinning check
      (`AuthenticationController.resolveClientIp`) trust that header - if
      the edge doesn't sanitize it, both are spoofable.

## Security

- [ ] **Consider TOTP as an MFA alternative or addition.** The current
      MFA implementation is OTP-based (email/SMS) via the same
      `OtpStore` mechanism as registration and password reset - reuses
      tested infrastructure, but makes every MFA login depend on
      notification-service being reachable, and email/SMS OTP is
      generally considered weaker than TOTP against SIM-swap/email
      compromise. Revisit if that tradeoff stops being acceptable.
- [ ] **Secrets management.** `jwt.secret`, DB/Redis passwords, and the
      super-admin seed password are all plain environment variables
      today. Fine for a single deploy target; worth moving to Vault/AWS
      Secrets Manager/K8s Secrets + External Secrets Operator once
      there's more than one environment to keep in sync.
- [ ] **Content-Security-Policy header.** `Referrer-Policy` is set;
      Spring Security's framework defaults cover
      `X-Content-Type-Options`/`X-Frame-Options`/HSTS already, but
      there's still no explicit CSP. Lower priority since this is a JSON
      API, not an HTML-serving app, except for `/swagger-ui.html`.
- [ ] **Tenant existence validation.** `POST /tenants/{tenantId}/users`
      (SUPER_ADMIN) writes the path's `tenantId` straight onto the new
      user without confirming that tenant actually exists in
      tenant-management-service.
- [ ] Consider bumping BCrypt strength from the default (10) to 12 and
      making it configurable via property.

## Operational

- [ ] `.github/workflows/ci.yml` needs a `PLATFORM_REPO_TOKEN` repo
      secret (read access to `IotMining/iotmining` and `IotMining/common`)
      added under Settings before it can run at all - and its first real
      run should be watched closely, since it was only verified via a
      local simulation of the checkout layout, not a live runner.
- [ ] Automate the OWASP dependency-check CVE scan (the `security-audit`
      Maven profile exists, needs an NVD API key and a few minutes - fine
      for CI, not something to run on every local build). Natural to add
      as a second job in `ci.yml` once the first job is confirmed working.
- [ ] Real DB migrations (Flyway/Liquibase) instead of
      `spring.jpa.hibernate.ddl-auto=update`. Matches the rest of this
      platform's current convention, so not unique to this service, but
      worth a platform-wide look eventually.
- [ ] Validate this service under more than one replica in a real
      environment - ShedLock and batched cleanup make that believed-safe,
      but it hasn't been exercised against a real multi-instance
      deployment yet.
