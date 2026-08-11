package com.iotmining.services.auth.services;

import com.iotmining.services.auth.repository.RefreshTokenRepository;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("TokenCleanupService")
class TokenCleanupServiceTest {

    private static final int BATCH_SIZE = 500;

    @Mock private UserLoginDataRepository tokenRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private TokenCleanupService tokenCleanupService;

    @BeforeEach
    void setUp() {
        tokenCleanupService = new TokenCleanupService(tokenRepository, refreshTokenRepository);
        ReflectionTestUtils.setField(tokenCleanupService, "batchSize", BATCH_SIZE);
    }

    @Test
    @DisplayName("deletes one partial batch and stops when fewer rows than the batch size are returned")
    void stopsAfterAPartialBatch() {
        when(tokenRepository.deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(3);
        when(refreshTokenRepository.deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class)))
                .thenReturn(0);

        tokenCleanupService.removeExpiredTokens();

        verify(tokenRepository, times(1))
                .deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class));
        verify(refreshTokenRepository, times(1))
                .deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class));
    }

    @Test
    @DisplayName("keeps requesting batches while a batch comes back full-sized")
    void loopsWhileBatchesAreFull() {
        when(tokenRepository.deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(BATCH_SIZE, BATCH_SIZE, 42);
        when(refreshTokenRepository.deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class)))
                .thenReturn(0);

        tokenCleanupService.removeExpiredTokens();

        verify(tokenRepository, times(3))
                .deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class));
    }

    @Test
    @DisplayName("never loops more than the per-run batch cap, even if every batch stays full")
    void stopsAtTheBatchCapWithoutHangingOnAnEndlessBacklog() {
        when(tokenRepository.deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(BATCH_SIZE);
        when(refreshTokenRepository.deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class)))
                .thenReturn(0);

        tokenCleanupService.removeExpiredTokens();

        verify(tokenRepository, times(20))
                .deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class));
    }

    @Test
    @DisplayName("survives login-data repository failures so the scheduler keeps running")
    void toleratesRepositoryFailure() {
        doThrow(new RuntimeException("db down"))
                .when(tokenRepository).deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class));
        when(refreshTokenRepository.deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class)))
                .thenReturn(0);

        assertThatCode(() -> tokenCleanupService.removeExpiredTokens()).doesNotThrowAnyException();
        verify(refreshTokenRepository).deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class));
    }

    @Test
    @DisplayName("survives refresh-token repository failures so the scheduler keeps running")
    void toleratesRefreshTokenRepositoryFailure() {
        when(tokenRepository.deleteBatchByTokenExpirationTimeBefore(any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(0);
        doThrow(new RuntimeException("db down"))
                .when(refreshTokenRepository).deleteBatchByExpiryDateBefore(any(Instant.class), any(Pageable.class));

        assertThatCode(() -> tokenCleanupService.removeExpiredTokens()).doesNotThrowAnyException();
    }
}
