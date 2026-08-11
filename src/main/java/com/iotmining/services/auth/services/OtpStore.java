package com.iotmining.services.auth.services;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OTP generation/verification, scoped by a {@code purpose} so the same
 * identifier (e.g. one email) can hold independent, non-colliding OTP
 * records for different flows at once - registration, password reset, and
 * login MFA all use this same mechanism rather than three copies of it.
 * {@code PURPOSE_SIGNUP} intentionally matches this class's original
 * hardcoded "signup" segment, so existing signup-flow Redis keys are
 * unaffected by this generalization.
 */
@Component
@RequiredArgsConstructor
public class OtpStore {

    public static final String PURPOSE_SIGNUP = "signup";
    public static final String PURPOSE_PASSWORD_RESET = "password-reset";
    public static final String PURPOSE_LOGIN_MFA = "login-mfa";

    private final RedisTemplate<String, Object> redis;
    private final SecureRandom random = new SecureRandom();

    private String key(String purpose, String identifier) { return "otp:" + purpose + ":" + identifier.toLowerCase(); }
    private String rlKey(String purpose, String identifier) { return "otp:" + purpose + ":rl:" + identifier.toLowerCase(); }

    public String generateCode() { return String.format("%06d", random.nextInt(1_000_000)); }
    public String generateProspectUserId() { return UUID.randomUUID().toString(); }

    private String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public void saveNew(String purpose, String identifier, String otp, Map<String,Object> extra, Duration ttl) {
        String salt = Long.toHexString(random.nextLong());
        String otpHash = sha256(salt + ":" + otp);
        Map<String,Object> payload = new HashMap<>(extra);
        payload.put("otpHash", otpHash);
        payload.put("salt", salt);
        redis.opsForValue().set(key(purpose, identifier), payload, ttl);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> get(String purpose, String identifier) {
        Object v = redis.opsForValue().get(key(purpose, identifier));
        return v == null ? null : (Map<String, Object>) v;
    }

    public boolean verify(String purpose, String identifier, String otp) {
        Map<String,Object> v = get(purpose, identifier);
        if (v == null) return false;
        String salt = (String) v.get("salt");
        String expected = (String) v.get("otpHash");
        if (salt == null || expected == null) return false;
        return expected.equals(sha256(salt + ":" + otp));
    }

    public int incrementAttempts(String purpose, String identifier) {
        Map<String,Object> v = get(purpose, identifier);
        if (v == null) return 0;
        int attempts = ((Number) v.getOrDefault("attempts", 0)).intValue() + 1;
        v.put("attempts", attempts);
        String redisKey = key(purpose, identifier);
        Long ttlSec = redis.getExpire(redisKey);
        Duration ttl = (ttlSec == null || ttlSec <= 0) ? Duration.ofSeconds(1) : Duration.ofSeconds(ttlSec);
        redis.opsForValue().set(redisKey, v, ttl);
        return attempts;
    }

    public void replaceOtp(String purpose, String identifier, String newOtp, Map<String,Object> extra, Duration ttl) {
        saveNew(purpose, identifier, newOtp, extra, ttl);
    }

    public void ensureResendBudget(String purpose, String identifier, int maxPerHour) {
        String rk = rlKey(purpose, identifier);
        Long cnt = redis.opsForValue().increment(rk);
        if (cnt != null && cnt == 1) redis.expire(rk, Duration.ofHours(1));
        if (cnt != null && cnt > maxPerHour) throw new RuntimeException("Resend limit reached");
    }

    public void delete(String purpose, String identifier) { redis.delete(key(purpose, identifier)); }
}
