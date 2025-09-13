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

@Component
@RequiredArgsConstructor
public class OtpStore {

    private final RedisTemplate<String, Object> redis;
    private final SecureRandom random = new SecureRandom();

    private String key(String identifier) { return "otp:signup:" + identifier.toLowerCase(); }
    private String rlKey(String identifier) { return "otp:signup:rl:" + identifier.toLowerCase(); }

    public String generateCode() { return String.format("%06d", random.nextInt(1_000_000)); }
    public String generateProspectUserId() { return UUID.randomUUID().toString(); }

    private String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public void saveNew(String identifier, String otp, Map<String,Object> extra, Duration ttl) {
        String salt = Long.toHexString(random.nextLong());
        String otpHash = sha256(salt + ":" + otp);
        Map<String,Object> payload = new HashMap<>(extra);
        payload.put("otpHash", otpHash);
        payload.put("salt", salt);
        redis.opsForValue().set(key(identifier), payload, ttl);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> get(String identifier) {
        Object v = redis.opsForValue().get(key(identifier));
        return v == null ? null : (Map<String, Object>) v;
    }

    public boolean verify(String identifier, String otp) {
        Map<String,Object> v = get(identifier);
        if (v == null) return false;
        String salt = (String) v.get("salt");
        String expected = (String) v.get("otpHash");
        if (salt == null || expected == null) return false;
        return expected.equals(sha256(salt + ":" + otp));
    }

    public int incrementAttempts(String identifier) {
        Map<String,Object> v = get(identifier);
        if (v == null) return 0;
        int attempts = ((Number) v.getOrDefault("attempts", 0)).intValue() + 1;
        v.put("attempts", attempts);
        Long ttlSec = redis.getExpire(key(identifier));
        java.time.Duration ttl = (ttlSec == null || ttlSec <= 0) ? Duration.ofSeconds(1) : Duration.ofSeconds(ttlSec);
        redis.opsForValue().set(key(identifier), v, ttl);
        return attempts;
    }

    public void replaceOtp(String identifier, String newOtp, Map<String,Object> extra, Duration ttl) {
        saveNew(identifier, newOtp, extra, ttl);
    }

    public void ensureResendBudget(String identifier, int maxPerHour) {
        String rk = rlKey(identifier);
        Long cnt = redis.opsForValue().increment(rk);
        if (cnt != null && cnt == 1) redis.expire(rk, Duration.ofHours(1));
        if (cnt != null && cnt > maxPerHour) throw new RuntimeException("Resend limit reached");
    }

    public void delete(String identifier) { redis.delete(key(identifier)); }
}
