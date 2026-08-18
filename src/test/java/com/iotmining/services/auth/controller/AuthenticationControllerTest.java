package com.iotmining.services.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotmining.services.auth.dto.AuthResponseDTO;
import com.iotmining.services.auth.dto.UserCreateDTO;
import com.iotmining.services.auth.dto.UserCredentialDTO;
import com.iotmining.services.auth.dto.UserSummaryDTO;
import com.iotmining.services.auth.entity.RefreshToken;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.exceptions.GlobalExceptionHandler;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.services.RefreshTokenService;
import com.iotmining.services.auth.services.UserService;
import com.iotmining.services.auth.support.TestDataFactory;
import com.iotmining.services.auth.util.JwtTokenProvider;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link AuthenticationController} using standalone MockMvc.
 *
 * <p>Scope: request mapping, request validation, response contract, and cookie
 * handling. Spring Security filters and {@code @PreAuthorize} rules are not part
 * of a standalone setup and are intentionally out of scope here.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationController")
class AuthenticationControllerTest {

    private static final String REFRESH_COOKIE = "refresh_token";

    @Mock private UserService userService;
    @Mock private RefreshTokenService refreshTokenService;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        TestDataFactory.initJwtProvider();
        AuthenticationController controller =
                new AuthenticationController(userService, refreshTokenService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    // ==============================================================================
    // LOGIN
    // ==============================================================================
    @Nested
    @DisplayName("POST /api/v1/auth/login")
    class Login {

        @Test
        @DisplayName("returns 200 with access token and a hardened refresh cookie")
        void loginSuccess() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            String accessToken = JwtTokenProvider.generateAccessToken(user);
            when(userService.verify(any(UserCredentialDTO.class))).thenReturn(successLoginResponse(accessToken));
            RefreshToken refreshToken = TestDataFactory.refreshToken(user, "127.0.0.1",
                    Instant.now().plus(Duration.ofDays(7)));
            when(refreshTokenService.createRefreshToken(eq(user.getUserId()), anyString()))
                    .thenReturn(refreshToken);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson("john.doe", "Str0ng@Pass")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.statusCode").value(200))
                    .andExpect(jsonPath("$.message").value("Login successful"))
                    .andExpect(jsonPath("$.data.accessToken").value(accessToken))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE,
                            containsString(REFRESH_COOKIE + "=" + refreshToken.getToken())))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Secure")));
        }

        @Test
        @DisplayName("binds the refresh token to the first X-Forwarded-For hop")
        void loginBindsClientIpBehindProxy() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            String accessToken = JwtTokenProvider.generateAccessToken(user);
            when(userService.verify(any(UserCredentialDTO.class))).thenReturn(successLoginResponse(accessToken));
            when(refreshTokenService.createRefreshToken(eq(user.getUserId()), anyString()))
                    .thenReturn(TestDataFactory.refreshToken(user, "203.0.113.7",
                            Instant.now().plus(Duration.ofDays(7))));

            mockMvc.perform(post("/api/v1/auth/login")
                            .header("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson("john.doe", "Str0ng@Pass")))
                    .andExpect(status().isOk());

            ArgumentCaptor<String> ipCaptor = ArgumentCaptor.forClass(String.class);
            verify(refreshTokenService).createRefreshToken(eq(user.getUserId()), ipCaptor.capture());
            assertThat(ipCaptor.getValue()).isEqualTo("203.0.113.7");
        }

        @Test
        @DisplayName("returns 401 without a refresh cookie for bad credentials")
        void loginInvalidCredentials() throws Exception {
            Map<String, Object> failure = new HashMap<>();
            failure.put("statusCode", 401);
            failure.put("message", "Invalid username or password");
            when(userService.verify(any(UserCredentialDTO.class))).thenReturn(failure);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson("john.doe", "wrong")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message").value("Invalid username or password"))
                    .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));

            verify(refreshTokenService, never()).createRefreshToken(any(UUID.class), anyString());
        }

        @Test
        @DisplayName("returns 400 with field errors for a blank password")
        void loginValidationFailure() throws Exception {
            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson("john.doe", "")))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.password").value("Password is mandatory"));

            verify(userService, never()).verify(any(UserCredentialDTO.class));
        }

        @Test
        @DisplayName("does not issue a refresh cookie when MFA is required")
        void loginWithMfaRequiredSkipsRefreshCookie() throws Exception {
            Map<String, Object> mfaRequired = new HashMap<>();
            mfaRequired.put("statusCode", 200);
            mfaRequired.put("message", "MFA verification required");
            mfaRequired.put("mfaRequired", true);
            mfaRequired.put("identifier", "john.doe@iotmining.com");
            when(userService.verify(any(UserCredentialDTO.class))).thenReturn(mfaRequired);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson("john.doe", "Str0ng@Pass")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.mfaRequired").value(true))
                    .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));

            verify(refreshTokenService, never()).createRefreshToken(any(UUID.class), anyString());
        }

        private Map<String, Object> successLoginResponse(String accessToken) {
            Map<String, Object> response = new HashMap<>();
            response.put("statusCode", 200);
            response.put("message", "Login successful");
            response.put("data", new AuthResponseDTO(accessToken, true));
            return response;
        }

        private String loginJson(String username, String password) throws Exception {
            return objectMapper.writeValueAsString(new UserCredentialDTO(username, password));
        }
    }

    // ==============================================================================
    // REFRESH
    // ==============================================================================
    @Nested
    @DisplayName("POST /api/v1/auth/refresh")
    class Refresh {

        @Test
        @DisplayName("returns 400 when the refresh cookie is missing")
        void missingCookie() throws Exception {
            mockMvc.perform(post("/api/v1/auth/refresh"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("Refresh Token Cookie missing"));
        }

        @Test
        @DisplayName("clears the cookie when the token is unknown")
        void unknownToken() throws Exception {
            when(refreshTokenService.findByToken("stale-token")).thenReturn(Optional.empty());

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie(REFRESH_COOKIE, "stale-token")))
                    .andExpect(status().isOk()) // current contract: cookie-clearing responses use 200
                    .andExpect(jsonPath("$.message").value(containsString("login again")))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));
        }

        @Test
        @DisplayName("revokes the whole token family when the request IP differs from the bound IP")
        void ipMismatchRevokesSession() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            RefreshToken token = TestDataFactory.refreshToken(user, "198.51.100.9",
                    Instant.now().plus(Duration.ofDays(1)));
            when(refreshTokenService.findByToken(token.getToken())).thenReturn(Optional.of(token));

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie(REFRESH_COOKIE, token.getToken())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value(containsString("Unusual activity")))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

            verify(refreshTokenService).revokeFamily(token.getFamilyId());
        }

        @Test
        @DisplayName("revokes the whole token family when an already-rotated-away token is replayed")
        void reuseOfARevokedTokenRevokesTheWholeFamily() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            RefreshToken token = TestDataFactory.refreshToken(user, null,
                    Instant.now().plus(Duration.ofDays(1)));
            token.setRevoked(true);
            when(refreshTokenService.findByToken(token.getToken())).thenReturn(Optional.of(token));

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie(REFRESH_COOKIE, token.getToken())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value(containsString("Unusual activity")))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

            verify(refreshTokenService).revokeFamily(token.getFamilyId());
            verify(refreshTokenService, never()).verifyExpiration(any());
            verify(refreshTokenService, never()).rotateRefreshToken(any());
        }

        @Test
        @DisplayName("rotates the refresh token and issues a new access token")
        void rotatesTokenOnSuccess() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            RefreshToken current = TestDataFactory.refreshToken(user, null,
                    Instant.now().plus(Duration.ofDays(1)));
            RefreshToken rotated = TestDataFactory.refreshToken(user, null,
                    Instant.now().plus(Duration.ofDays(7)));
            when(refreshTokenService.findByToken(current.getToken())).thenReturn(Optional.of(current));
            when(refreshTokenService.verifyExpiration(current)).thenReturn(current);
            when(refreshTokenService.rotateRefreshToken(current)).thenReturn(rotated);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie(REFRESH_COOKIE, current.getToken())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andExpect(header().string(HttpHeaders.SET_COOKIE,
                            containsString(REFRESH_COOKIE + "=" + rotated.getToken())));
        }

        @Test
        @DisplayName("clears the cookie when the token has expired")
        void expiredToken() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            RefreshToken token = TestDataFactory.refreshToken(user, null,
                    Instant.now().minus(Duration.ofMinutes(1)));
            when(refreshTokenService.findByToken(token.getToken())).thenReturn(Optional.of(token));
            when(refreshTokenService.verifyExpiration(token))
                    .thenThrow(new RuntimeException("Refresh token was expired"));

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie(REFRESH_COOKIE, token.getToken())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Invalid or Expired Refresh Token"))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));
        }
    }

    // ==============================================================================
    // TOKEN VALIDATION (gateway contract)
    // ==============================================================================
    @Nested
    @DisplayName("GET /api/v1/auth/validate")
    class Validate {

        @Test
        @DisplayName("returns 200 with identity headers for a valid token")
        void validToken() throws Exception {
            String tenantId = UUID.randomUUID().toString();
            String token = signedToken("john.doe", tenantId, 60_000);

            mockMvc.perform(get("/api/v1/auth/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-User-Id", "john.doe"))
                    .andExpect(header().string("X-Tenant-Id", tenantId));
        }

        @Test
        @DisplayName("returns 401 when the Bearer prefix is missing")
        void missingBearerPrefix() throws Exception {
            mockMvc.perform(get("/api/v1/auth/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Basic abc123"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("returns 401 for an expired token")
        void expiredToken() throws Exception {
            String token = signedToken("john.doe", UUID.randomUUID().toString(), -60_000);

            mockMvc.perform(get("/api/v1/auth/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("returns 401 for a malformed token")
        void malformedToken() throws Exception {
            mockMvc.perform(get("/api/v1/auth/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer not.a.jwt"))
                    .andExpect(status().isUnauthorized());
        }

        private String signedToken(String subject, String tenantId, long ttlMs) {
            return Jwts.builder()
                    .subject(subject)
                    .claim("tenantId", tenantId)
                    .claim("roles", "ROLE_USER")
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + ttlMs))
                    .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(TestDataFactory.TEST_JWT_SECRET_B64)))
                    .compact();
        }
    }

    // ==============================================================================
    // LOGOUT
    // ==============================================================================
    @Test
    @DisplayName("POST /api/v1/auth/logout clears the refresh cookie")
    void logoutClearsCookie() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logout successful"))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString(REFRESH_COOKIE + "=;")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));
    }

    // ==============================================================================
    // REGISTRATION
    // ==============================================================================
    @Nested
    @DisplayName("POST /api/v1/auth/register")
    class Register {

        @Test
        @DisplayName("returns 202 when the OTP was dispatched")
        void registerAccepted() throws Exception {
            Map<String, Object> accepted = new HashMap<>();
            accepted.put("statusCode", 202);
            accepted.put("message", "OTP sent successfully");
            when(userService.registerInit(any())).thenReturn(accepted);

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(TestDataFactory.validRegistration())))
                    .andExpect(status().isAccepted())
                    .andExpect(jsonPath("$.message").value("OTP sent successfully"));
        }

        @Test
        @DisplayName("returns 400 with validation details for an invalid payload")
        void registerValidationFailure() throws Exception {
            var invalid = TestDataFactory.validRegistration();
            invalid.setEmail("not-an-email");
            invalid.setPassword("weak");

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalid)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.statusCode").value(400))
                    .andExpect(jsonPath("$.error").exists());

            verify(userService, never()).registerInit(any());
        }

        @Test
        @DisplayName("rejects an underage registrant")
        void registerUnderageRejected() throws Exception {
            var underage = TestDataFactory.validRegistration();
            underage.setDateOfBirth(java.time.LocalDate.now().minusYears(17).toString());

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(underage)))
                    .andExpect(status().isBadRequest());

            verify(userService, never()).registerInit(any());
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/register/verify and /otp/resend")
    class OtpEndpoints {

        @Test
        @DisplayName("verify passes the service status code through (201 on success)")
        void verifyOtpCreated() throws Exception {
            Map<String, Object> created = new HashMap<>();
            created.put("statusCode", 201);
            created.put("message", "Registration successful!");
            when(userService.verifyOtp(any())).thenReturn(created);

            mockMvc.perform(post("/api/v1/auth/register/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@example.com\",\"otp\":\"123456\",\"type\":\"EMAIL\"}"))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("verify rejects a payload without an OTP")
        void verifyOtpMissingCode() throws Exception {
            mockMvc.perform(post("/api/v1/auth/register/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@example.com\",\"type\":\"EMAIL\"}"))
                    .andExpect(status().isBadRequest());

            verify(userService, never()).verifyOtp(any());
        }

        @Test
        @DisplayName("resend passes the service status code through (429 when throttled)")
        void resendThrottled() throws Exception {
            Map<String, Object> throttled = new HashMap<>();
            throttled.put("statusCode", 429);
            throttled.put("message", "Too many attempts");
            when(userService.resendOtp(any())).thenReturn(throttled);

            mockMvc.perform(post("/api/v1/auth/otp/resend")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@example.com\"}"))
                    .andExpect(status().isTooManyRequests());
        }
    }

    // ==============================================================================
    // PASSWORD RESET
    // ==============================================================================
    @Nested
    @DisplayName("password reset")
    class PasswordReset {

        @Test
        @DisplayName("init passes the service status code through")
        void initPassesThroughStatus() throws Exception {
            Map<String, Object> accepted = new HashMap<>();
            accepted.put("statusCode", 200);
            accepted.put("message", "If an account exists for that identifier, a password reset code has been sent.");
            when(userService.initiatePasswordReset(any())).thenReturn(accepted);

            mockMvc.perform(post("/api/v1/auth/password-reset/init")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@example.com\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value(containsString("If an account exists")));
        }

        @Test
        @DisplayName("init rejects a payload without an identifier")
        void initRejectsMissingIdentifier() throws Exception {
            mockMvc.perform(post("/api/v1/auth/password-reset/init")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isBadRequest());

            verify(userService, never()).initiatePasswordReset(any());
        }

        @Test
        @DisplayName("confirm passes the service status code through (429 when the attempt cap is hit)")
        void confirmPassesThroughStatus() throws Exception {
            Map<String, Object> throttled = new HashMap<>();
            throttled.put("statusCode", 429);
            throttled.put("message", "Too many incorrect attempts. Please request a new code.");
            when(userService.confirmPasswordReset(any())).thenReturn(throttled);

            mockMvc.perform(post("/api/v1/auth/password-reset/confirm")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@example.com\",\"otp\":\"123456\",\"newPassword\":\"NewStr0ng@Pass\"}"))
                    .andExpect(status().isTooManyRequests());
        }

        @Test
        @DisplayName("confirm rejects a weak new password before reaching the service")
        void confirmRejectsWeakPassword() throws Exception {
            mockMvc.perform(post("/api/v1/auth/password-reset/confirm")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@example.com\",\"otp\":\"123456\",\"newPassword\":\"weak\"}"))
                    .andExpect(status().isBadRequest());

            verify(userService, never()).confirmPasswordReset(any());
        }
    }

    // ==============================================================================
    // CHANGE PASSWORD / OWN PROFILE
    // ==============================================================================
    @Nested
    @DisplayName("change password / my profile")
    class ChangePasswordAndProfile {

        @Test
        @DisplayName("change-password passes the service status code through")
        void changePasswordPassesThroughStatus() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            Map<String, Object> ok = new HashMap<>();
            ok.put("statusCode", 200);
            ok.put("message", "Password changed successfully. Please log in again on other devices.");
            when(userService.changePassword(eq(user.getUserId()), any())).thenReturn(ok);

            mockMvc.perform(post("/api/v1/auth/change-password")
                            .principal(authenticationFor(user))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"currentPassword\":\"OldStr0ng@Pass\",\"newPassword\":\"NewStr0ng@Pass\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value(containsString("Please log in again")));
        }

        @Test
        @DisplayName("change-password rejects a weak new password before reaching the service")
        void changePasswordRejectsWeakPassword() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");

            mockMvc.perform(post("/api/v1/auth/change-password")
                            .principal(authenticationFor(user))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"currentPassword\":\"OldStr0ng@Pass\",\"newPassword\":\"weak\"}"))
                    .andExpect(status().isBadRequest());

            verify(userService, never()).changePassword(any(), any());
        }

        @Test
        @DisplayName("GET /me returns the authenticated caller's own profile")
        void getMyProfile() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            com.iotmining.services.auth.dto.UserProfileDTO profile = new com.iotmining.services.auth.dto.UserProfileDTO();
            profile.setUserId(user.getUserId());
            profile.setUsername("john.doe");
            profile.setEmail(user.getEmail());
            when(userService.getUserProfile(user.getUserId())).thenReturn(profile);

            mockMvc.perform(get("/api/v1/auth/me")
                            .principal(authenticationFor(user)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value("john.doe"));
        }

        private Authentication authenticationFor(User user) {
            UserPrincipal principal = new UserPrincipal(user);
            return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        }
    }

    // ==============================================================================
    // MFA
    // ==============================================================================
    @Nested
    @DisplayName("MFA")
    class Mfa {

        @Test
        @DisplayName("verify issues a refresh cookie on success, same as a completed login")
        void verifyIssuesRefreshCookieOnSuccess() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            String accessToken = JwtTokenProvider.generateAccessToken(user);
            Map<String, Object> success = new HashMap<>();
            success.put("statusCode", 200);
            success.put("message", "Login successful");
            success.put("data", new AuthResponseDTO(accessToken, true));
            when(userService.verifyMfa(any())).thenReturn(success);
            RefreshToken refreshToken = TestDataFactory.refreshToken(user, "127.0.0.1",
                    Instant.now().plus(Duration.ofDays(7)));
            when(refreshTokenService.createRefreshToken(eq(user.getUserId()), anyString()))
                    .thenReturn(refreshToken);

            mockMvc.perform(post("/api/v1/auth/mfa/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@iotmining.com\",\"otp\":\"123456\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.data.accessToken").value(accessToken))
                    .andExpect(header().string(HttpHeaders.SET_COOKIE,
                            containsString(REFRESH_COOKIE + "=" + refreshToken.getToken())));
        }

        @Test
        @DisplayName("verify passes through a rejection without a refresh cookie")
        void verifyPassesThroughRejection() throws Exception {
            Map<String, Object> rejected = new HashMap<>();
            rejected.put("statusCode", 400);
            rejected.put("message", "Invalid or expired code.");
            when(userService.verifyMfa(any())).thenReturn(rejected);

            mockMvc.perform(post("/api/v1/auth/mfa/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"identifier\":\"john.doe@iotmining.com\",\"otp\":\"000000\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
        }

        @Test
        @DisplayName("enable requires authentication and delegates to the caller's own user id")
        void enableDelegatesToCallersUserId() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            Map<String, Object> enabled = Map.of("statusCode", 200, "message", "Multi-factor authentication enabled.");
            when(userService.enableMfa(user.getUserId())).thenReturn(enabled);

            mockMvc.perform(post("/api/v1/auth/mfa/enable")
                            .principal(authenticationFor(user)))
                    .andExpect(status().isOk());

            verify(userService).enableMfa(user.getUserId());
        }

        @Test
        @DisplayName("disable passes the current password through and delegates to the caller's own user id")
        void disableDelegatesToCallersUserId() throws Exception {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            Map<String, Object> disabled = Map.of("statusCode", 200, "message", "Multi-factor authentication disabled.");
            when(userService.disableMfa(user.getUserId(), "Str0ng@Pass")).thenReturn(disabled);

            mockMvc.perform(post("/api/v1/auth/mfa/disable")
                            .principal(authenticationFor(user))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"currentPassword\":\"Str0ng@Pass\"}"))
                    .andExpect(status().isOk());

            verify(userService).disableMfa(user.getUserId(), "Str0ng@Pass");
        }

        private Authentication authenticationFor(User user) {
            UserPrincipal principal = new UserPrincipal(user);
            return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        }
    }

    // ==============================================================================
    // TENANT USER MANAGEMENT
    // ==============================================================================
    @Nested
    @DisplayName("Tenant user endpoints")
    class TenantUsers {

        @Test
        @DisplayName("POST /users creates the employee inside the admin's own tenant")
        void addUserToMyTenant() throws Exception {
            User admin = TestDataFactory.user("admin.user", "ROLE_ADMIN");
            Map<String, Object> created = new HashMap<>();
            created.put("statusCode", 201);
            created.put("message", "User added to organization");
            when(userService.createUserInternal(any(UserCreateDTO.class), eq(admin.getTenantId())))
                    .thenReturn(created);

            mockMvc.perform(post("/api/v1/auth/users")
                            .principal(authenticationFor(admin))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(employeeJson()))
                    .andExpect(status().isCreated());

            verify(userService).createUserInternal(any(UserCreateDTO.class), eq(admin.getTenantId()));
        }

        @Test
        @DisplayName("POST /tenants/{tenantId}/users targets the tenant from the path")
        void addUserToSpecificTenant() throws Exception {
            UUID targetTenant = UUID.randomUUID();
            Map<String, Object> created = new HashMap<>();
            created.put("statusCode", 201);
            created.put("message", "User added to organization");
            when(userService.createUserInternal(any(UserCreateDTO.class), eq(targetTenant)))
                    .thenReturn(created);

            mockMvc.perform(post("/api/v1/auth/tenants/{tenantId}/users", targetTenant)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(employeeJson()))
                    .andExpect(status().isCreated());

            verify(userService).createUserInternal(any(UserCreateDTO.class), eq(targetTenant));
        }

        @Test
        @DisplayName("GET /tenants/{tenantId}/users-list returns the tenant's users")
        void listTenantUsers() throws Exception {
            User admin = TestDataFactory.user("admin.user", "ROLE_ADMIN");
            UUID tenantId = admin.getTenantId();
            UserSummaryDTO summary = new UserSummaryDTO();
            summary.setUserId(UUID.randomUUID());
            summary.setUsername("employee1");
            summary.setEmail("employee1@acme.com");
            summary.setAccessLevel("ROLE_USER");
            when(userService.findUsersByTenantId(tenantId)).thenReturn(List.of(summary));

            mockMvc.perform(get("/api/v1/auth/tenants/{tenantId}/users-list", tenantId)
                            .principal(authenticationFor(admin)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].username").value("employee1"))
                    .andExpect(jsonPath("$[0].accessLevel").value("ROLE_USER"));
        }

        private Authentication authenticationFor(User user) {
            UserPrincipal principal = new UserPrincipal(user);
            return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        }

        private String employeeJson() {
            return "{\"username\":\"employee1\",\"email\":\"employee1@acme.com\","
                    + "\"firstName\":\"Emma\",\"lastName\":\"Ployee\",\"password\":\"Empl0yee@1\"}";
        }
    }
}
