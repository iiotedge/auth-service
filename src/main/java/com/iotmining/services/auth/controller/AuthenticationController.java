package com.iotmining.services.auth.controller;

import com.iotmining.services.auth.dto.AuthResponseDTO;
import com.iotmining.services.auth.dto.OtpResendRequest;
import com.iotmining.services.auth.dto.OtpVerifyRequest;
import com.iotmining.services.auth.dto.RegisterDTO;
import com.iotmining.services.auth.dto.UserCreateDTO;
import com.iotmining.services.auth.dto.UserCredentialDTO;
import com.iotmining.services.auth.dto.UserSummaryDTO;
import com.iotmining.services.auth.annotation.RateLimited;
import com.iotmining.services.auth.entity.RefreshToken;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.services.RefreshTokenService;
import com.iotmining.services.auth.services.UserService;
import com.iotmining.services.auth.util.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private static final String REFRESH_COOKIE_NAME = "refresh_token";
    private static final String REFRESH_COOKIE_PATH = "/api/v1/auth";

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;

    @RateLimited
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody UserCredentialDTO credentials,
                                                       HttpServletRequest request) {
        Map<String, Object> result = userService.verify(credentials);
        int statusCode = (Integer) result.get("statusCode");

        if (statusCode == HttpStatus.OK.value() && result.get("data") instanceof AuthResponseDTO authResponse) {
            UUID userId = UUID.fromString(JwtTokenProvider.extractUserId(authResponse.getAccessToken()));
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userId, resolveClientIp(request));
            return ResponseEntity.status(statusCode)
                    .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(refreshToken).toString())
                    .body(result);
        }

        return ResponseEntity.status(statusCode).body(result);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(
            @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshTokenCookie,
            HttpServletRequest request) {

        if (refreshTokenCookie == null || refreshTokenCookie.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("statusCode", 400, "message", "Refresh Token Cookie missing"));
        }

        Optional<RefreshToken> tokenOpt = refreshTokenService.findByToken(refreshTokenCookie);
        if (tokenOpt.isEmpty()) {
            return clearedCookieResponse("Refresh token not found, please login again.");
        }

        RefreshToken token = tokenOpt.get();
        String clientIp = resolveClientIp(request);
        if (token.getIpAddress() != null && !token.getIpAddress().equals(clientIp)) {
            refreshTokenService.deleteByToken(token.getToken());
            return clearedCookieResponse("Unusual activity detected, please login again.");
        }

        try {
            refreshTokenService.verifyExpiration(token);
        } catch (RuntimeException e) {
            return clearedCookieResponse("Invalid or Expired Refresh Token");
        }

        RefreshToken rotated = refreshTokenService.rotateRefreshToken(token);
        String newAccessToken = JwtTokenProvider.generateAccessToken(token.getUser());

        Map<String, Object> body = new HashMap<>();
        body.put("accessToken", newAccessToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(rotated).toString())
                .body(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshTokenCookie) {
        if (refreshTokenCookie != null && !refreshTokenCookie.isBlank()) {
            refreshTokenService.deleteByToken(refreshTokenCookie);
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .body(Map.of("message", "Logout successful"));
    }

    @GetMapping("/validate")
    public ResponseEntity<Void> validate(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String token = authHeader.substring(7);
        if (!Boolean.TRUE.equals(JwtTokenProvider.validateToken(token))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Claims claims = JwtTokenProvider.extractAllClaims(token);
        return ResponseEntity.ok()
                .header("X-User-Id", claims.getSubject())
                .header("X-Tenant-Id", claims.get("tenantId", String.class))
                .build();
    }

    @RateLimited
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterDTO request) {
        Map<String, Object> result = userService.registerInit(request);
        return ResponseEntity.status((Integer) result.get("statusCode")).body(result);
    }

    @RateLimited
    @PostMapping("/register/verify")
    public ResponseEntity<Map<String, Object>> verifyOtp(@Valid @RequestBody OtpVerifyRequest request) {
        Map<String, Object> result = userService.verifyOtp(request);
        return ResponseEntity.status((Integer) result.get("statusCode")).body(result);
    }

    @RateLimited
    @PostMapping("/otp/resend")
    public ResponseEntity<Map<String, Object>> resendOtp(@Valid @RequestBody OtpResendRequest request) {
        Map<String, Object> result = userService.resendOtp(request);
        return ResponseEntity.status((Integer) result.get("statusCode")).body(result);
    }

    @PostMapping("/users")
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN')")
    public ResponseEntity<Map<String, Object>> addUserToMyTenant(@Valid @RequestBody UserCreateDTO request,
                                                                   Authentication authentication) {
        UUID tenantId = ((UserPrincipal) authentication.getPrincipal()).getUser().getTenantId();
        Map<String, Object> result = userService.createUserInternal(request, tenantId);
        return ResponseEntity.status((Integer) result.get("statusCode")).body(result);
    }

    // SUPER_ADMIN only: lets a caller create a user in an arbitrary tenant by id.
    @PostMapping("/tenants/{tenantId}/users")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Map<String, Object>> addUserToTenant(@PathVariable UUID tenantId,
                                                                 @Valid @RequestBody UserCreateDTO request) {
        Map<String, Object> result = userService.createUserInternal(request, tenantId);
        return ResponseEntity.status((Integer) result.get("statusCode")).body(result);
    }

    @GetMapping("/tenants/{tenantId}/users-list")
    public ResponseEntity<List<UserSummaryDTO>> listTenantUsers(@PathVariable UUID tenantId,
                                                                  Authentication authentication) {
        UserPrincipal caller = (UserPrincipal) authentication.getPrincipal();
        boolean isSuperAdmin = caller.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_SUPER_ADMIN"));

        if (!isSuperAdmin && !tenantId.equals(caller.getUser().getTenantId())) {
            throw new AccessDeniedException("Not authorized to view users for this tenant.");
        }

        return ResponseEntity.ok(userService.findUsersByTenantId(tenantId));
    }

    private ResponseEntity<Map<String, Object>> clearedCookieResponse(String message) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .body(Map.of("statusCode", 200, "message", message));
    }

    private ResponseCookie buildRefreshCookie(RefreshToken refreshToken) {
        long maxAgeSeconds = Math.max(0,
                refreshToken.getExpiryDate().getEpochSecond() - java.time.Instant.now().getEpochSecond());
        return ResponseCookie.from(REFRESH_COOKIE_NAME, refreshToken.getToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .build();
    }

    private ResponseCookie clearRefreshCookie() {
        return ResponseCookie.from(REFRESH_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(0)
                .build();
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
