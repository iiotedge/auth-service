package com.iotmining.services.auth.util;

import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Function;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.iotmining.common.data.tenant.TenantAccessLevel;
import com.iotmining.common.data.tenant.TenantType;
import com.iotmining.services.auth.dto.UserLoginDataDTO;
import com.iotmining.services.auth.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    private final static long JWT_EXPIRATION_MIN = 30;
    private static final long EXPIRATION_TIME_MS = 300000; // 5 min
//    private static String SECRET_KEY;

//    @Value("${jwt.secret}")
//    private static String secretKeyBase64="Vlo2vcFdiXGgWqZLEpLw6kk99sH8/4odgC2XgZV0IbA=";

    @Value("${jwt.secret}")
    private String secretKeyBase64;

    private static SecretKey secretKey;

//    public JwtTokenProvider() {
//        try {
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
//            SecretKey secretKey = keyGenerator.generateKey();
//            this.secretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//    }


    @PostConstruct
    public void init() {
        secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKeyBase64));
    }

    //    private static SecretKey getKey() {
//        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
//    }
    private static SecretKey getKey() {
        return secretKey;
    }

    private static TenantType determineTenantType(List<String> roles) {
        if (roles.contains("ROLE_SUPER_ADMIN")) {
            return TenantType.ORGANIZATION;
        } else if (roles.contains("ROLE_ADMIN")) {
            return TenantType.COMPANY;
        } else {
            return TenantType.USER;
        }
    }

    private static TenantAccessLevel determineAccessLevel(TenantType tenantType) {
        return switch (tenantType) {
            case ORGANIZATION -> TenantAccessLevel.SUPER;
            case COMPANY -> TenantAccessLevel.ADMIN;
            case USER -> TenantAccessLevel.READ_ONLY;
        };
    }

    /**
     * Generate JWT Token containing user role, tenantId and access level
     */
    public static UserLoginDataDTO generateToken(UserPrincipal userDetails, List<String> roles) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userDetails.getUser().getUserId());
        claims.put("role", roles);
        claims.put("username", userDetails.getUser().getUsername());
        claims.put("userFullName", userDetails.getUser().getFirstName() +" "+ userDetails.getUser().getLastName());

        // 👇 Add TenantType and AccessLevel
        TenantType tenantType = determineTenantType(roles);
        claims.put("tenantType", tenantType.name());
        claims.put("tenantId", userDetails.getUser().getTenantId());

        TenantAccessLevel accessLevel = determineAccessLevel(tenantType);
        claims.put("accessLevel", accessLevel.name());

        UserLoginDataDTO userLoginDataDTO;

        LocalDateTime currentLocalDateTime = LocalDateTime.now();
        Date currentDate = Date.from(currentLocalDateTime.atZone(ZoneId.systemDefault()).toInstant());

        Date expireDate;
        LocalDateTime expireLocalDateForSuperAdmin = LocalDateTime.now().plusMinutes(JWT_EXPIRATION_MIN);
//        LocalDateTime expireLocalDateForOtherUser = LocalDateTime.now().plusSeconds(EXPIRATION_TIME_MS / 1000);
        LocalDateTime expireLocalDateForOtherUser = LocalDateTime.now().plusMinutes(JWT_EXPIRATION_MIN);

        String token;
        if (roles.contains("ROLE_SUPER_ADMIN")) {
            claims.put("superAdmin", true);
            claims.put("accessLevel", "full");
            expireDate = Date.from(expireLocalDateForSuperAdmin.atZone(ZoneId.systemDefault()).toInstant());
        } else {
            claims.put("superAdmin", false);
            claims.put("accessLevel", "low");
            expireDate = Date.from(expireLocalDateForOtherUser.atZone(ZoneId.systemDefault()).toInstant());
        }

        token = Jwts.builder()
                .subject(userDetails.getUsername())
                .claims(claims)
                .issuedAt(currentDate)
                .expiration(expireDate)
                .signWith(getKey())
                .compact();

        userLoginDataDTO = new UserLoginDataDTO(
                userDetails.getUser().getUserId(),
                null,
                null,
                token,
                currentLocalDateTime,
                expireLocalDateForSuperAdmin,
                null,
                null,
                null,
                true,
                userDetails.getUser()
        );

        return userLoginDataDTO;
    }
    // ADD this method at the bottom (no changes to your existing generateToken method)
    public static String issueInternalToken(String issuer, String prospectId, int ttlMinutes) {
        Map<String,Object> claims = new HashMap<>();
        claims.put("scope","internal");
        claims.put("aud","notification-service");
        claims.put("prospectId", prospectId);
        Date now = new Date();
        Date exp = new Date(now.getTime() + ttlMinutes * 60_000L);
        return Jwts.builder()
                .subject("internal-" + prospectId)
                .issuer(issuer)
                .claims(claims)
                .issuedAt(now)
                .expiration(exp)
                .signWith(getKey())
                .compact();
    }



    public static String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private static <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public static Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private static boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private static Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public static Boolean verifyToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public static Boolean validateToken(String token) {
        try {
            final String userName = extractUserName(token);
            return (userName != null && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }
}
