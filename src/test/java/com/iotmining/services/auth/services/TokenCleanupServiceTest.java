package com.iotmining.services.auth.services;

import com.iotmining.services.auth.repository.RefreshTokenRepository;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("TokenCleanupService")
class TokenCleanupServiceTest {

    @Mock private UserLoginDataRepository tokenRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks private TokenCleanupService tokenCleanupService;

    @Test
    @DisplayName("deletes login records whose token expired before now")
    void deletesExpiredTokens() {
        LocalDateTime before = LocalDateTime.now();

        tokenCleanupService.removeExpiredTokens();

        ArgumentCaptor<LocalDateTime> cutoff = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(tokenRepository).deleteByTokenExpirationTimeBefore(cutoff.capture());
        assertThat(cutoff.getValue()).isAfterOrEqualTo(before);
        assertThat(cutoff.getValue()).isBeforeOrEqualTo(LocalDateTime.now());
    }

    @Test
    @DisplayName("also deletes refresh tokens that expired before now")
    void deletesExpiredRefreshTokens() {
        Instant before = Instant.now();

        tokenCleanupService.removeExpiredTokens();

        ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
        verify(refreshTokenRepository).deleteByExpiryDateBefore(cutoff.capture());
        assertThat(cutoff.getValue()).isAfterOrEqualTo(before);
    }

    @Test
    @DisplayName("survives login-data repository failures so the scheduler keeps running")
    void toleratesRepositoryFailure() {
        doThrow(new RuntimeException("db down"))
                .when(tokenRepository).deleteByTokenExpirationTimeBefore(any(LocalDateTime.class));

        assertThatCode(() -> tokenCleanupService.removeExpiredTokens()).doesNotThrowAnyException();
        verify(refreshTokenRepository).deleteByExpiryDateBefore(any(Instant.class));
    }

    @Test
    @DisplayName("survives refresh-token repository failures so the scheduler keeps running")
    void toleratesRefreshTokenRepositoryFailure() {
        doThrow(new RuntimeException("db down"))
                .when(refreshTokenRepository).deleteByExpiryDateBefore(any(Instant.class));

        assertThatCode(() -> tokenCleanupService.removeExpiredTokens()).doesNotThrowAnyException();
    }
}
