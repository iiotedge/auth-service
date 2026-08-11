package com.iotmining.services.auth.services;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.function.IntSupplier;

import com.iotmining.services.auth.repository.RefreshTokenRepository;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupService {

    /**
     * Caps the work a single run can do, so a large backlog (e.g. after the
     * job was down for a while) can't turn one sweep into one giant
     * long-running delete/transaction. A backlog that doesn't fully drain
     * in one run just gets picked up by the next one.
     */
    private static final int MAX_BATCHES_PER_RUN = 20;

    private final UserLoginDataRepository tokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.cleanup.batch-size:500}")
    private int batchSize;

    // Use a cron expression or fixedRate.
    // fixedRate = 300000 (5 minutes) is usually better than 30s for database health.
    //
    // @SchedulerLock (see SchedulerLockConfig) ensures only one instance of
    // this service runs the sweep at a time - without it, every replica
    // would run the same DELETEs redundantly the moment this service scales
    // beyond one instance. lockAtMostFor is a safety ceiling in case an
    // instance dies mid-run without releasing the lock; lockAtLeastFor
    // prevents a very fast run from letting another instance re-acquire and
    // re-run the same sweep seconds later on a fast fixed-rate schedule.
    @Async
    @Scheduled(fixedRateString = "${app.cleanup.token-interval:300000}")
    @SchedulerLock(name = "removeExpiredTokens", lockAtMostFor = "PT10M", lockAtLeastFor = "PT30S")
    @Transactional
    public void removeExpiredTokens() {
        LocalDateTime loginDataCutoff = LocalDateTime.now();
        Instant refreshTokenCutoff = Instant.now();
        int effectiveBatchSize = Math.max(1, batchSize);

        int loginDataDeleted = deleteInBatches(effectiveBatchSize,
                () -> tokenRepository.deleteBatchByTokenExpirationTimeBefore(loginDataCutoff, PageRequest.of(0, effectiveBatchSize)));
        log.info("Cleanup Task: removed {} expired login-data row(s) at {}", loginDataDeleted, loginDataCutoff);

        int refreshTokensDeleted = deleteInBatches(effectiveBatchSize,
                () -> refreshTokenRepository.deleteBatchByExpiryDateBefore(refreshTokenCutoff, PageRequest.of(0, effectiveBatchSize)));
        log.info("Cleanup Task: removed {} expired refresh token(s) at {}", refreshTokensDeleted, refreshTokenCutoff);
    }

    private int deleteInBatches(int effectiveBatchSize, IntSupplier deleteOneBatch) {
        int totalDeleted = 0;
        try {
            for (int i = 0; i < MAX_BATCHES_PER_RUN; i++) {
                int deleted = deleteOneBatch.getAsInt();
                totalDeleted += deleted;
                if (deleted < effectiveBatchSize) {
                    return totalDeleted;
                }
            }
            log.warn("Cleanup Task: hit the per-run batch cap ({} x {}) - remaining backlog will drain on the next run",
                    MAX_BATCHES_PER_RUN, effectiveBatchSize);
        } catch (Exception e) {
            log.error("Cleanup Task failed after deleting {} row(s) this run", totalDeleted, e);
        }
        return totalDeleted;
    }
}
