package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.RefreshToken;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.repository.RefreshTokenRepository;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.support.TestDataFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService")
class RefreshTokenServiceTest {

    private static final long SEVEN_DAYS_MS = Duration.ofDays(7).toMillis();

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private UserRepository userRepository;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, userRepository);
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenDurationMs", SEVEN_DAYS_MS);
    }

    @Nested
    @DisplayName("createRefreshToken")
    class CreateRefreshToken {

        @Test
        @DisplayName("issues an opaque token bound to the user, IP, and configured expiry, starting a fresh family")
        void createsTokenWithIpBinding() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            Instant before = Instant.now();
            RefreshToken token = refreshTokenService.createRefreshToken(user.getUserId(), "203.0.113.7");

            assertThat(token.getUser()).isSameAs(user);
            assertThat(token.getIpAddress()).isEqualTo("203.0.113.7");
            assertThat(UUID.fromString(token.getToken())).isNotNull(); // opaque, unguessable format
            assertThat(token.getExpiryDate())
                    .isCloseTo(before.plusMillis(SEVEN_DAYS_MS), within(5, java.time.temporal.ChronoUnit.SECONDS));
            assertThat(token.getFamilyId()).isNotNull();
            assertThat(token.isRevoked()).isFalse();
        }

        @Test
        @DisplayName("revokes any previous token first (single active session per user)")
        void revokesExistingTokenBeforeIssuing() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            refreshTokenService.createRefreshToken(user.getUserId(), "203.0.113.7");

            InOrder inOrder = inOrder(refreshTokenRepository);
            inOrder.verify(refreshTokenRepository).deleteByUser(user);
            inOrder.verify(refreshTokenRepository).flush();
            inOrder.verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("fails for an unknown user")
        void failsForUnknownUser() {
            UUID unknownId = UUID.randomUUID();
            when(userRepository.findById(unknownId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.createRefreshToken(unknownId, "203.0.113.7"))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining(unknownId.toString());
            verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("backward-compatible overload issues a token without IP binding")
        void overloadWithoutIp() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            RefreshToken token = refreshTokenService.createRefreshToken(user.getUserId());

            assertThat(token.getIpAddress()).isNull();
        }

        @Test
        @DisplayName("createRefreshTokenByUsername resolves the user before issuing")
        void createsByUsername() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            when(userRepository.findByUsername("john.doe")).thenReturn(Optional.of(user));
            when(userRepository.findById(user.getUserId())).thenReturn(Optional.of(user));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            RefreshToken token = refreshTokenService.createRefreshTokenByUsername("john.doe", "203.0.113.7");

            assertThat(token.getUser()).isSameAs(user);
            assertThat(token.getIpAddress()).isEqualTo("203.0.113.7");
        }

        @Test
        @DisplayName("createRefreshTokenByUsername fails for an unknown username")
        void failsForUnknownUsername() {
            when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.createRefreshTokenByUsername("ghost", "203.0.113.7"))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("ghost");
        }
    }

    @Nested
    @DisplayName("verifyExpiration")
    class VerifyExpiration {

        @Test
        @DisplayName("returns the token when it is still valid")
        void returnsValidToken() {
            RefreshToken token = TestDataFactory.refreshToken(
                    TestDataFactory.user("john.doe", "ROLE_USER"), "203.0.113.7",
                    Instant.now().plus(Duration.ofDays(1)));

            assertThat(refreshTokenService.verifyExpiration(token)).isSameAs(token);
            verify(refreshTokenRepository, never()).delete(any());
        }

        @Test
        @DisplayName("deletes the token and fails when it has expired")
        void rejectsExpiredToken() {
            RefreshToken token = TestDataFactory.refreshToken(
                    TestDataFactory.user("john.doe", "ROLE_USER"), "203.0.113.7",
                    Instant.now().minus(Duration.ofMinutes(1)));

            assertThatThrownBy(() -> refreshTokenService.verifyExpiration(token))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("expired");
            verify(refreshTokenRepository).delete(token);
        }
    }

    @Nested
    @DisplayName("rotateRefreshToken")
    class RotateRefreshToken {

        @Test
        @DisplayName("issues a new token value while preserving the original IP binding and family")
        void rotationPreservesIpBindingAndFamily() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            RefreshToken oldToken = TestDataFactory.refreshToken(user, "203.0.113.7",
                    Instant.now().plus(Duration.ofDays(1)));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            RefreshToken rotated = refreshTokenService.rotateRefreshToken(oldToken);

            assertThat(rotated.getIpAddress()).isEqualTo("203.0.113.7");
            assertThat(rotated.getToken()).isNotEqualTo(oldToken.getToken());
            assertThat(rotated.getFamilyId()).isEqualTo(oldToken.getFamilyId());
            assertThat(rotated.isRevoked()).isFalse();
        }

        @Test
        @DisplayName("marks the presented token revoked instead of deleting it")
        void marksOldTokenRevoked() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            RefreshToken oldToken = TestDataFactory.refreshToken(user, null,
                    Instant.now().plus(Duration.ofDays(1)));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            refreshTokenService.rotateRefreshToken(oldToken);

            assertThat(oldToken.isRevoked()).isTrue();
            assertThat(oldToken.getRevokedAt()).isNotNull();
            verify(refreshTokenRepository, never()).delete(any());
            verify(refreshTokenRepository, never()).deleteByUser(any());
            verify(refreshTokenRepository, never()).flush();
        }
    }

    @Nested
    @DisplayName("revokeFamily")
    class RevokeFamily {

        @Test
        @DisplayName("delegates to the repository with the family id and a timestamp")
        void revokesTheFamily() {
            UUID familyId = UUID.randomUUID();

            refreshTokenService.revokeFamily(familyId);

            verify(refreshTokenRepository).revokeFamily(org.mockito.ArgumentMatchers.eq(familyId), any(Instant.class));
        }
    }

    @Nested
    @DisplayName("revokeAllForUser")
    class RevokeAllForUser {

        @Test
        @DisplayName("deletes every token row for the user")
        void deletesAllTokensForUser() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");

            refreshTokenService.revokeAllForUser(user);

            verify(refreshTokenRepository).deleteByUser(user);
        }
    }

    @Nested
    @DisplayName("deleteByToken")
    class DeleteByToken {

        @Test
        @DisplayName("deletes the entity when the token exists")
        void deletesExistingToken() {
            RefreshToken token = TestDataFactory.refreshToken(
                    TestDataFactory.user("john.doe", "ROLE_USER"), null,
                    Instant.now().plus(Duration.ofDays(1)));
            when(refreshTokenRepository.findByToken(token.getToken())).thenReturn(Optional.of(token));

            refreshTokenService.deleteByToken(token.getToken());

            verify(refreshTokenRepository).delete(token);
        }

        @Test
        @DisplayName("is a no-op when the token does not exist")
        void ignoresUnknownToken() {
            when(refreshTokenRepository.findByToken("unknown")).thenReturn(Optional.empty());

            refreshTokenService.deleteByToken("unknown");

            verify(refreshTokenRepository, never()).delete(any());
        }
    }
}
