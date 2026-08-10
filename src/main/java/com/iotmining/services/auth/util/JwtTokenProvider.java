package com.iotmining.services.auth.util;

import com.iotmining.common.data.tenant.TenantAccessLevel;
import com.iotmining.common.data.tenant.TenantType;
import com.iotmining.services.auth.dto.UserLoginDataDTO;
import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKeyBase64;

    @Value("${app.jwt.expiration-min:30}") // Default to 30 if missing in yml
    private long jwtExpirationMinConfig;

    @Value("${app.jwt.admin-expiration-min:1440}") // Default to 1440 (24h) if missing
    private long jwtAdminExpirationMinConfig;

    private static SecretKey secretKey;
    private static long JWT_EXPIRATION_MIN;
    private static long JWT_EXPIRATION_ADMIN_MIN;

    @PostConstruct
    public void init() {
        // 1. Initialize Key
        secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKeyBase64));

        // 2. Map Instance Config to Static Variables
        JWT_EXPIRATION_MIN = this.jwtExpirationMinConfig;
        JWT_EXPIRATION_ADMIN_MIN = this.jwtAdminExpirationMinConfig;
    }

    private static SecretKey getKey() { return secretKey; }

    private static TenantType determineTenantType(List<String> roles) {
        if (roles == null || roles.isEmpty()) return TenantType.ORGANIZATION; // Default Context

        if (roles.contains("ROLE_SUPER_ADMIN")) {
            return TenantType.PLATFORM;
        }
        if (roles.contains("ROLE_MANAGER")) {
            return TenantType.SUB_TENANT;
        }
        return TenantType.ORGANIZATION;
    }

    private static TenantAccessLevel determineAccessLevel(TenantType tenantType, List<String> roles) {
        if (tenantType == TenantType.PLATFORM) {
            return TenantAccessLevel.SUPER_ADMIN;
        }
        if (tenantType == TenantType.ORGANIZATION && roles.contains("ROLE_ADMIN")) {
            return TenantAccessLevel.TENANT_ADMIN;
        }
        if (tenantType == TenantType.SUB_TENANT || roles.contains("ROLE_MANAGER")) {
            return TenantAccessLevel.OPERATIONAL;
        }
        return TenantAccessLevel.READ_ONLY;
    }

    public static UserLoginDataDTO generateToken(UserPrincipal userDetails, List<String> roles) {
        return createTokenInternal(userDetails.getUser(), roles);
    }

    public static String generateAccessToken(User user) {
        List<String> roleNames = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        return createTokenInternal(user, roleNames).getAccessToken();
    }

    private static UserLoginDataDTO createTokenInternal(User user, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getUserId());
        claims.put("role", roles);
        claims.put("username", user.getUsername());
        claims.put("userFullName", user.getFirstName() + " " + user.getLastName());

        TenantType tenantType = determineTenantType(roles);
        claims.put("tenantType", tenantType.name());
        claims.put("tenantId", user.getTenantId());

        TenantAccessLevel accessLevel = determineAccessLevel(tenantType, roles);
        claims.put("accessLevel", accessLevel.name());

        boolean isSuperAdmin = roles.contains("ROLE_SUPER_ADMIN");

        // Use the static variables populated from Config
        long expirationMinutes = isSuperAdmin ? JWT_EXPIRATION_ADMIN_MIN : JWT_EXPIRATION_MIN;

        if (isSuperAdmin) {
            claims.put("superAdmin", true);
        } else {
            claims.put("superAdmin", false);
        }

        Instant nowInstant = Instant.now();
        Instant expiresInstant = nowInstant.plus(expirationMinutes, ChronoUnit.MINUTES);

        Date now = Date.from(nowInstant);
        Date expDate = Date.from(expiresInstant);

        String token = Jwts.builder()
                .subject(user.getUsername())
                .claims(claims)
                .issuedAt(now)
                .expiration(expDate)
                .signWith(getKey())
                .compact();

        // Convert back to System Default Zone ONLY for the DTO (Display purposes)
        LocalDateTime nowLDT = LocalDateTime.ofInstant(nowInstant, ZoneId.systemDefault());
        LocalDateTime expiresLDT = LocalDateTime.ofInstant(expiresInstant, ZoneId.systemDefault());

        return new UserLoginDataDTO(user.getUserId(), null, null, token, nowLDT, expiresLDT, null, null, null, true, user);
    }

    public static String issueInternalToken(String issuer, String prospectId, int ttlMinutes) {
        return issueInternalToken(issuer, prospectId, "notification-service", ttlMinutes);
    }

    /**
     * Mints a short-lived service-to-service token scoped to a specific downstream
     * audience (e.g. "tenant-management-service"). Callers on the receiving end
     * must check both scope=internal and that aud matches their own service name,
     * so a token minted for one downstream service can't be replayed against another.
     */
    public static String issueInternalToken(String issuer, String subject, String audience, int ttlMinutes) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "internal");
        claims.put("aud", audience);
        claims.put("prospectId", subject);

        Instant nowInstant = Instant.now();
        Instant expInstant = nowInstant.plus(ttlMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .subject("internal-" + subject)
                .issuer(issuer)
                .claims(claims)
                .issuedAt(Date.from(nowInstant))
                .expiration(Date.from(expInstant))
                .signWith(getKey())
                .compact();
    }

    public static String extractUserName(String token) { return extractClaim(token, Claims::getSubject); }

    public static String extractUserId(String token) { return extractClaim(token, c -> c.get("userId", String.class)); }

    private static <T> T extractClaim(String token, Function<Claims, T> resolver) { return resolver.apply(extractAllClaims(token)); }

    public static Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(getKey()).build().parseSignedClaims(token).getPayload();
    }

    public static Boolean verifyToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public static Boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) { return false; }
    }

    private static boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}

