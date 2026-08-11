package com.iotmining.services.auth.support;

import com.iotmining.services.auth.dto.RegisterDTO;
import com.iotmining.services.auth.entity.RefreshToken;
import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.util.JwtTokenProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Central factory for test fixtures shared across the auth-service test suite.
 *
 * <p>JwtTokenProvider keeps its signing key and expiration windows in static
 * fields populated by {@code @PostConstruct}. Tests must call
 * {@link #initJwtProvider()} (or {@link #initJwtProvider(long, long)}) before
 * exercising any code path that signs or parses tokens.</p>
 */
public final class TestDataFactory {

    /** Base64 of a 48-byte key — comfortably above the 256-bit HMAC-SHA minimum. */
    public static final String TEST_JWT_SECRET_B64 = Base64.getEncoder()
            .encodeToString("auth-service-unit-test-signing-key-0123456789abcdef".getBytes(StandardCharsets.UTF_8));

    public static final long DEFAULT_EXPIRATION_MIN = 30;
    public static final long DEFAULT_ADMIN_EXPIRATION_MIN = 1440;

    private TestDataFactory() {
    }

    public static void initJwtProvider() {
        initJwtProvider(DEFAULT_EXPIRATION_MIN, DEFAULT_ADMIN_EXPIRATION_MIN);
    }

    public static void initJwtProvider(long expirationMin, long adminExpirationMin) {
        JwtTokenProvider provider = new JwtTokenProvider();
        ReflectionTestUtils.setField(provider, "secretKeyBase64", TEST_JWT_SECRET_B64);
        ReflectionTestUtils.setField(provider, "jwtExpirationMinConfig", expirationMin);
        ReflectionTestUtils.setField(provider, "jwtAdminExpirationMinConfig", adminExpirationMin);
        provider.init();
    }

    public static User user(String username, String... roleNames) {
        User user = new User();
        user.setUserId(UUID.randomUUID());
        user.setTenantId(UUID.randomUUID());
        user.setUsername(username);
        user.setPassword("$2a$10$encoded-password-hash");
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(username + "@iotmining.com");
        user.setPhoneNumber("+919876543210");
        user.setIsAccountActive(true);
        Set<Role> roles = Arrays.stream(roleNames)
                .map(Role::new)
                .collect(Collectors.toCollection(HashSet::new));
        user.setRoles(roles);
        return user;
    }

    public static RefreshToken refreshToken(User user, String ipAddress, Instant expiryDate) {
        RefreshToken token = new RefreshToken();
        token.setId(1L);
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setIpAddress(ipAddress);
        token.setExpiryDate(expiryDate);
        token.setFamilyId(UUID.randomUUID());
        token.setRevoked(false);
        return token;
    }

    public static RegisterDTO validRegistration() {
        return RegisterDTO.builder()
                .username("john.doe")
                .organizationName("Acme IoT Solutions")
                .firstName("John")
                .lastName("Doe")
                .gender("MALE")
                .dateOfBirth("1990-01-15")
                .password("Str0ng@Pass")
                .email("john.doe@example.com")
                .phoneNumber("+919876543210")
                .roles(List.of("ROLE_USER"))
                .build();
    }
}
