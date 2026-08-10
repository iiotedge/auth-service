package com.iotmining.services.auth.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("OtpStore")
class OtpStoreTest {

    @Mock
    private RedisTemplate<String, Object> redis;
    @Mock
    private ValueOperations<String, Object> valueOperations;

    private OtpStore otpStore;

    @BeforeEach
    void setUp() {
        lenient().when(redis.opsForValue()).thenReturn(valueOperations);
        otpStore = new OtpStore(redis);
    }

    @Test
    @DisplayName("generateCode always returns a 6-digit numeric string")
    void generateCodeIsSixDigits() {
        for (int i = 0; i < 20; i++) {
            String code = otpStore.generateCode();
            assertThat(code).hasSize(6);
            assertThat(code).matches("\\d{6}");
        }
    }

    @Test
    @DisplayName("generateProspectUserId returns a parseable UUID string")
    void generateProspectUserIdIsUuid() {
        String id = otpStore.generateProspectUserId();
        assertThat(java.util.UUID.fromString(id)).isNotNull();
    }

    @Nested
    @DisplayName("verify")
    class Verify {

        @Test
        @DisplayName("returns true when the OTP hashes match")
        void verifyReturnsTrueForCorrectOtp() {
            org.mockito.ArgumentCaptor<Object> payloadCaptor = org.mockito.ArgumentCaptor.forClass(Object.class);

            otpStore.saveNew("test@example.com", "123456", Map.of("prospectId", "p1"), Duration.ofMinutes(5));
            verify(valueOperations).set(eq("otp:signup:test@example.com"), payloadCaptor.capture(), eq(Duration.ofMinutes(5)));

            @SuppressWarnings("unchecked")
            Map<String, Object> stored = (Map<String, Object>) payloadCaptor.getValue();
            when(valueOperations.get("otp:signup:test@example.com")).thenReturn(stored);

            assertThat(otpStore.verify("test@example.com", "123456")).isTrue();
        }

        @Test
        @DisplayName("returns false when the OTP does not match")
        void verifyReturnsFalseForWrongOtp() {
            org.mockito.ArgumentCaptor<Object> payloadCaptor = org.mockito.ArgumentCaptor.forClass(Object.class);
            otpStore.saveNew("test@example.com", "123456", Map.of(), Duration.ofMinutes(5));
            verify(valueOperations).set(eq("otp:signup:test@example.com"), payloadCaptor.capture(), any(Duration.class));

            @SuppressWarnings("unchecked")
            Map<String, Object> stored = (Map<String, Object>) payloadCaptor.getValue();
            when(valueOperations.get("otp:signup:test@example.com")).thenReturn(stored);

            assertThat(otpStore.verify("test@example.com", "000000")).isFalse();
        }

        @Test
        @DisplayName("returns false when there is no stored OTP for the identifier")
        void verifyReturnsFalseWhenMissing() {
            when(valueOperations.get("otp:signup:missing@example.com")).thenReturn(null);
            assertThat(otpStore.verify("missing@example.com", "123456")).isFalse();
        }

        @Test
        @DisplayName("returns false when the stored record is missing hash/salt fields")
        void verifyReturnsFalseWhenRecordIncomplete() {
            when(valueOperations.get("otp:signup:partial@example.com")).thenReturn(new HashMap<>());
            assertThat(otpStore.verify("partial@example.com", "123456")).isFalse();
        }
    }

    @Test
    @DisplayName("get returns null when nothing is stored")
    void getReturnsNullWhenMissing() {
        when(valueOperations.get("otp:signup:nobody@example.com")).thenReturn(null);
        assertThat(otpStore.get("nobody@example.com")).isNull();
    }

    @Nested
    @DisplayName("incrementAttempts")
    class IncrementAttempts {

        @Test
        @DisplayName("returns 0 and does nothing when there is no stored record")
        void returnsZeroWhenMissing() {
            when(valueOperations.get("otp:signup:missing@example.com")).thenReturn(null);
            assertThat(otpStore.incrementAttempts("missing@example.com")).isZero();
            verify(valueOperations, never()).set(anyString(), any(), any(Duration.class));
        }

        @Test
        @DisplayName("increments the attempts counter and re-saves with the remaining TTL")
        void incrementsAndPreservesRemainingTtl() {
            Map<String, Object> existing = new HashMap<>(Map.of("otpHash", "h", "salt", "s", "attempts", 2));
            when(valueOperations.get("otp:signup:test@example.com")).thenReturn(existing);
            when(redis.getExpire("otp:signup:test@example.com")).thenReturn(120L);

            int attempts = otpStore.incrementAttempts("test@example.com");

            assertThat(attempts).isEqualTo(3);
            verify(valueOperations).set(eq("otp:signup:test@example.com"), any(), eq(Duration.ofSeconds(120)));
        }

        @Test
        @DisplayName("falls back to a 1-second TTL when the key has no remaining expiry")
        void fallsBackToOneSecondWhenExpiryUnknown() {
            Map<String, Object> existing = new HashMap<>(Map.of("attempts", 0));
            when(valueOperations.get("otp:signup:test@example.com")).thenReturn(existing);
            when(redis.getExpire("otp:signup:test@example.com")).thenReturn(null);

            otpStore.incrementAttempts("test@example.com");

            verify(valueOperations).set(eq("otp:signup:test@example.com"), any(), eq(Duration.ofSeconds(1)));
        }
    }

    @Test
    @DisplayName("replaceOtp overwrites the stored OTP the same way saveNew does")
    void replaceOtpStoresNewValue() {
        otpStore.replaceOtp("test@example.com", "654321", Map.of(), Duration.ofMinutes(5));
        verify(valueOperations).set(eq("otp:signup:test@example.com"), any(), eq(Duration.ofMinutes(5)));
    }

    @Nested
    @DisplayName("ensureResendBudget")
    class EnsureResendBudget {

        @Test
        @DisplayName("allows the request and sets a 1-hour expiry on the first call")
        void firstCallSetsExpiry() {
            when(valueOperations.increment("otp:signup:rl:test@example.com")).thenReturn(1L);
            otpStore.ensureResendBudget("test@example.com", 3);
            verify(redis).expire("otp:signup:rl:test@example.com", Duration.ofHours(1));
        }

        @Test
        @DisplayName("allows the request and does not re-set expiry on subsequent calls")
        void subsequentCallsDoNotResetExpiry() {
            when(valueOperations.increment("otp:signup:rl:test@example.com")).thenReturn(2L);
            otpStore.ensureResendBudget("test@example.com", 3);
            verify(redis, never()).expire(anyString(), any(Duration.class));
        }

        @Test
        @DisplayName("throws once the count exceeds the configured maximum")
        void throwsWhenBudgetExceeded() {
            when(valueOperations.increment("otp:signup:rl:test@example.com")).thenReturn(4L);
            org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                    () -> otpStore.ensureResendBudget("test@example.com", 3));
        }
    }

    @Test
    @DisplayName("delete removes the stored OTP key")
    void deleteRemovesKey() {
        otpStore.delete("test@example.com");
        verify(redis, times(1)).delete("otp:signup:test@example.com");
    }
}
