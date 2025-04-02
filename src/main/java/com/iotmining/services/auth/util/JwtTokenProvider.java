package com.iotmining.services.auth.util;

import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.iotmining.services.auth.dto.UserLoginDataDTO;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.iotmining.services.auth.security.UserPrincipal;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

    private final static long JWT_EXPIRATION_MIN = 30;
    private static final long EXPIRATION_TIME_MS = 300000; // 5 min
    private static String SECRET_KEY;

    public JwtTokenProvider() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            SECRET_KEY = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static SecretKey getKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
    }

    public static UserLoginDataDTO generateToken(UserPrincipal userDetails, List<String> roles) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", roles);

        UserLoginDataDTO userLoginDataDTO;

        LocalDateTime currentLocalDateTime = LocalDateTime.now();
        Date currentDate = Date.from(currentLocalDateTime.atZone(ZoneId.systemDefault()).toInstant());

        Date expireDate;
        // For super admin
        LocalDateTime expireLocalDateForSuperAdmin = LocalDateTime.now().plusMinutes(JWT_EXPIRATION_MIN);
        // For normal user
        LocalDateTime expireLocalDateForOtherUser = LocalDateTime.now().plusSeconds(EXPIRATION_TIME_MS / 1000);

        String token;
        if (roles.contains("ROLE_SUPER_ADMIN")) {
            claims.put("superAdmin", true);
            claims.put("accessLevel", "full");
            expireDate = Date
                    .from(expireLocalDateForSuperAdmin.atZone(ZoneId.systemDefault()).toInstant());
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
        userLoginDataDTO = new UserLoginDataDTO(userDetails.getUser().getUserId(), null, null, token,
                currentLocalDateTime, expireLocalDateForSuperAdmin, null, null, null, true, userDetails.getUser());
        return userLoginDataDTO;
    }

    public static String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private static <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAlClaims(token);
        return claimResolver.apply(claims);
    }

    private static Claims extractAlClaims(String token) {
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
//            System.out.println("Here");
            return (userName != null && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }
}
