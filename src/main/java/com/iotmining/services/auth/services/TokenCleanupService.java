package com.iotmining.services.auth.services;

import java.time.Instant;
import java.time.LocalDateTime;

import com.iotmining.services.auth.repository.RefreshTokenRepository;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupService {

    private final UserLoginDataRepository tokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    // Use a cron expression or fixedRate.
    // fixedRate = 300000 (5 minutes) is usually better than 30s for database health.
    @Async
    @Scheduled(fixedRateString = "${app.cleanup.token-interval:300000}")
    @Transactional
    public void removeExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();

        try {
            // This is efficient: it generates a "DELETE FROM ... WHERE time < ?" query
            tokenRepository.deleteByTokenExpirationTimeBefore(now);
            log.info("Cleanup Task: Expired login-data tokens removed at {}", now);
        } catch (Exception e) {
            log.error("Cleanup Task Failed", e);
        }

        try {
            // RefreshTokenService already deletes-and-replaces on every
            // login/rotation, but a user who logs in once and never
            // refreshes again would otherwise leave one expired row forever.
            refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
            log.info("Cleanup Task: Expired refresh tokens removed at {}", now);
        } catch (Exception e) {
            log.error("Refresh token cleanup failed", e);
        }
    }
}