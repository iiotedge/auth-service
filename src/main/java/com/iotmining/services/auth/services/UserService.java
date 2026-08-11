package com.iotmining.services.auth.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotmining.common.base.notifications.dto.BaseRequest;
import com.iotmining.common.base.notifications.dto.BaseResponse;
import com.iotmining.common.base.notifications.dto.NotificationRequest;
import com.iotmining.common.base.notifications.dto.NotificationResponse;
import com.iotmining.common.base.notifications.enums.NotificationType;
import com.iotmining.services.auth.clients.NotificationClient;
import com.iotmining.services.auth.dto.*;
import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.exceptions.UserMessageException;
import com.iotmining.services.auth.repository.RoleRepository;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final UserLoginDataService userLoginDataService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    // External Services & Clients
    private final RestTemplate restTemplate;
    private final NotificationClient notificationClient;
    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final OtpStore otpStore;
    private final RefreshTokenService refreshTokenService;

    @Value("${tenant.service.url}")
    private String tenantServiceUrl;

    @Value("${notification.service.url:http://localhost:8087}")
    private String notificationBaseUrl;

    @Value("${account.lockout.max-attempts:5}")
    private int maxFailedLoginAttempts;

    @Value("${account.lockout.duration-minutes:15}")
    private long lockoutDurationMinutes;

    @Value("${otp.max.attempts:5}")
    private int maxOtpAttempts;

    @Value("${otp.resend.max.per.hour:3}")
    private int maxOtpResendsPerHour;

    // Constants
    private static final String REG_KEY_FMT = "reg:prospect:%s";
    private static final String IDX_KEY_FMT = "reg:index:%s:%s"; // type:identifier -> prospectId
    private static final Duration OTP_TTL = Duration.ofMinutes(5);
    // Longer than signup's OTP_TTL - a password-reset email/SMS is often
    // checked later than a live registration flow the user is actively in.
    private static final Duration PASSWORD_RESET_OTP_TTL = Duration.ofMinutes(15);
    // Login MFA is a synchronous flow (the user is actively waiting mid-login), same window as signup.
    private static final Duration MFA_OTP_TTL = Duration.ofMinutes(5);

    // ==================================================================================
    // 1. LOGIN FLOW
    // ==================================================================================
    public Map<String, Object> verify(UserCredentialDTO request) {
        Map<String, Object> response = new HashMap<>();
        log.info("Login attempt for user: {}", request.getUsername());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            if (!userPrincipal.isEnabled()) {
                throw new UserMessageException("Account is disabled. Please contact support.");
            }

            resetFailedLoginAttempts(userPrincipal.getUser());

            if (Boolean.TRUE.equals(userPrincipal.getUser().getMfaEnabled())) {
                return challengeMfa(userPrincipal.getUser());
            }

            List<String> roles = userPrincipal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            return buildSuccessfulLoginResponse(userPrincipal.getUser(), roles);

        } catch (LockedException e) {
            log.warn("Login blocked: account locked for {}", request.getUsername());
            response.put("message", "Account temporarily locked due to repeated failed login attempts. Try again later.");
            response.put("statusCode", 423);
            return response;
        } catch (BadCredentialsException e) {
            log.warn("Login failed: Bad credentials for {}", request.getUsername());
            recordFailedLoginAttempt(request.getUsername());
            response.put("message", "Invalid username or password");
            response.put("statusCode", 401);
            return response;
        } catch (Exception e) {
            log.error("Login unexpected error", e);
            response.put("message", "Internal Server Error");
            response.put("statusCode", 500);
            return response;
        }
    }

    private Map<String, Object> buildSuccessfulLoginResponse(User user, List<String> roles) {
        Map<String, Object> response = new HashMap<>();

        UserLoginDataDTO userLoginData = JwtTokenProvider.generateToken(new UserPrincipal(user), roles);
        userLoginData.setUser(user);
        userLoginDataService.addUserAsyncLoginData(userLoginData);

        AuthResponseDTO authResponseDTO = new AuthResponseDTO();
        authResponseDTO.setAccessToken(userLoginData.getConfirmationToken());
        authResponseDTO.setIsAccountActive(true);

        response.put("message", "Login successful");
        response.put("statusCode", 200);
        response.put("data", authResponseDTO);
        return response;
    }

    /**
     * Password already verified at this point - withholds the access token
     * and sends an OTP instead. No "data" key in the response, which is what
     * tells AuthenticationController.login() not to issue a refresh cookie
     * yet; the client must complete verifyMfa() first.
     */
    private Map<String, Object> challengeMfa(User user) {
        String identifier = (user.getEmail() != null && !user.getEmail().isBlank()) ? user.getEmail() : user.getUsername();
        String otp = otpStore.generateCode();
        otpStore.saveNew(OtpStore.PURPOSE_LOGIN_MFA, identifier, otp,
                Map.of("userId", user.getUserId().toString()), MFA_OTP_TTL);

        String channel = identifier.contains("@") ? "EMAIL" : "SMS";
        sendOtpInternalJwt(user.getUserId().toString(), channel, identifier, otp, "Your login verification code");

        Map<String, Object> response = new HashMap<>();
        response.put("statusCode", 200);
        response.put("message", "MFA verification required");
        response.put("mfaRequired", true);
        response.put("identifier", identifier);
        return response;
    }

    public Map<String, Object> verifyMfa(MfaVerifyRequest request) {
        Map<String, Object> resp = new HashMap<>();
        String identifier = request.getIdentifier().trim();

        // Same enforcement shape as the other OTP flows - capped attempts
        // before the code must be re-requested via a fresh login attempt.
        Map<String, Object> otpRecord = otpStore.get(OtpStore.PURPOSE_LOGIN_MFA, identifier);
        int attemptsSoFar = otpRecord == null ? 0 : ((Number) otpRecord.getOrDefault("attempts", 0)).intValue();
        if (attemptsSoFar >= maxOtpAttempts) {
            resp.put("statusCode", 429);
            resp.put("message", "Too many incorrect attempts. Please log in again.");
            return resp;
        }

        if (!otpStore.verify(OtpStore.PURPOSE_LOGIN_MFA, identifier, request.getOtp())) {
            otpStore.incrementAttempts(OtpStore.PURPOSE_LOGIN_MFA, identifier);
            resp.put("statusCode", 400);
            resp.put("message", "Invalid or expired code.");
            return resp;
        }

        Optional<User> userOpt = userRepository.findByUsernameOrEmail(identifier);
        if (userOpt.isEmpty()) {
            resp.put("statusCode", 400);
            resp.put("message", "Invalid or expired code.");
            return resp;
        }
        User user = userOpt.get();
        otpStore.delete(OtpStore.PURPOSE_LOGIN_MFA, identifier);

        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        return buildSuccessfulLoginResponse(user, roles);
    }

    public Map<String, Object> enableMfa(UUID userId) {
        Map<String, Object> resp = new HashMap<>();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        user.setMfaEnabled(true);
        userRepository.save(user);
        resp.put("statusCode", 200);
        resp.put("message", "Multi-factor authentication enabled.");
        return resp;
    }

    /** Requires the current password so a hijacked-but-valid session can't silently turn MFA off. */
    public Map<String, Object> disableMfa(UUID userId, String currentPassword) {
        Map<String, Object> resp = new HashMap<>();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            resp.put("statusCode", 401);
            resp.put("message", "Incorrect password.");
            return resp;
        }

        user.setMfaEnabled(false);
        userRepository.save(user);
        resp.put("statusCode", 200);
        resp.put("message", "Multi-factor authentication disabled.");
        return resp;
    }

    /**
     * Spring Security's DaoAuthenticationProvider hides "user not found" behind
     * BadCredentialsException by default (avoids username enumeration), so a
     * failed lookup here just means "not a real account" - nothing to record.
     */
    private void recordFailedLoginAttempt(String usernameOrEmail) {
        userRepository.findByUsernameOrEmail(usernameOrEmail).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= maxFailedLoginAttempts) {
                user.setLockedUntil(Instant.now().plus(Duration.ofMinutes(lockoutDurationMinutes)));
                log.warn("Account locked for {} minutes after {} failed login attempts: {}",
                        lockoutDurationMinutes, attempts, usernameOrEmail);
            }
            userRepository.save(user);
        });
    }

    private void resetFailedLoginAttempts(User user) {
        if (user.getFailedLoginAttempts() != 0 || user.getLockedUntil() != null) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }
    }

    // ==================================================================================
    // 2. REGISTRATION: PHASE 1 (INIT) - Saves State to Redis
    // ==================================================================================
    public Map<String, Object> registerInit(RegisterDTO request) {
        Map<String, Object> resp = new HashMap<>();
        log.info("Registration Init for email: {}", request.getEmail());

        try {
            if (request.getRoles() != null && request.getRoles().contains("ROLE_SUPER_ADMIN")) {
                throw new UserMessageException("Authorization Error: Cannot create Super Admin account via public API.");
            }

            if (userRepository.existsByUsername(request.getUsername())) {
                resp.put("statusCode", 409);
                resp.put("message", "Username already exists.");
                return resp;
            }

            final UUID prospectId = UUID.randomUUID();
            final String pId = prospectId.toString().toLowerCase(Locale.ROOT);
            final String otp = otpStore.generateCode();

            // Resolve Channel
            final String email = request.getEmail();
            final String phone = request.getPhoneNumber();
            final String resolvedChannel = resolveChannel(request.getOtpChannel(), phone, email);

            // Save to Redis
            saveOtpAndPending(pId, otp, request);

            // Send Notification
            boolean delivered = sendOtpInternalJwt(pId, resolvedChannel,
                    "EMAIL".equals(resolvedChannel) ? email : phone, otp);

            if (!delivered) {
                redis.delete(REG_KEY_FMT.formatted(pId)); // Cleanup
                throw new RuntimeException("Failed to deliver OTP via " + resolvedChannel);
            }

            resp.put("statusCode", 202);
            resp.put("message", "OTP sent successfully");
            resp.put("data", Map.of("prospectId", pId, "otpChannel", resolvedChannel));
            return resp;

        } catch (UserMessageException e) {
            resp.put("statusCode", 400); resp.put("message", e.getMessage()); return resp;
        } catch (Exception e) {
            log.error("Register Init Error", e);
            resp.put("statusCode", 500); resp.put("message", "Registration failed: " + e.getMessage()); return resp;
        }
    }

    // ==================================================================================
    // 3. REGISTRATION: PHASE 2 (VERIFY OTP & CREATE)
    // ==================================================================================
    // Using @Transactional so if User Save fails, Role assignments are rolled back in DB
    @Transactional(noRollbackFor = {RuntimeException.class}) // Manual rollback handled for TMS
    public Map<String, Object> verifyOtp(OtpVerifyRequest req) {
        Map<String, Object> resp = new HashMap<>();

        try {
            // 1. Validation & Resolution
            if (req.getIdentifier() == null || req.getType() == null) {
                resp.put("statusCode", 400); resp.put("message", "Identifier and Type required"); return resp;
            }

            final String type = req.getType().trim().toUpperCase(Locale.ROOT);
            final String rawId = req.getIdentifier().trim();
            final String normalizedId = "EMAIL".equals(type) ? rawId.toLowerCase(Locale.ROOT) : rawId;

            String prospectId = redis.opsForValue().get(indexKey(type, normalizedId));
            if (prospectId == null && looksLikeUuid(rawId)) prospectId = rawId.toLowerCase(Locale.ROOT);

            if (prospectId == null) {
                resp.put("statusCode", 404); resp.put("message", "Session expired or invalid."); return resp;
            }

            // 2. Verify OTP - capped at maxOtpAttempts wrong guesses (otpStore
            // already tracked "attempts" but nothing previously enforced a
            // limit on it, leaving OTP guessing effectively unbounded).
            Map<String, Object> otpRecord = otpStore.get(OtpStore.PURPOSE_SIGNUP, prospectId);
            int attemptsSoFar = otpRecord == null ? 0 : ((Number) otpRecord.getOrDefault("attempts", 0)).intValue();
            if (attemptsSoFar >= maxOtpAttempts) {
                resp.put("statusCode", 429);
                resp.put("message", "Too many incorrect attempts. Please request a new OTP.");
                return resp;
            }

            if (!otpStore.verify(OtpStore.PURPOSE_SIGNUP, prospectId, req.getOtp())) {
                otpStore.incrementAttempts(OtpStore.PURPOSE_SIGNUP, prospectId);
                resp.put("statusCode", 400); resp.put("message", "Invalid OTP"); return resp;
            }

            // 3. Load Data from Redis
            final String regKey = REG_KEY_FMT.formatted(prospectId);
            final String regJson = redis.opsForValue().get(regKey);
            if (regJson == null) {
                resp.put("statusCode", 404); resp.put("message", "Session data missing."); return resp;
            }
            RegisterDTO register = objectMapper.readValue(regJson, RegisterDTO.class);

            // ---------------------------------------------------------
            // STEP A: CREATE TENANT (Call TMS)
            // ---------------------------------------------------------
            CreateTenantRequest tenantRequest = new CreateTenantRequest();
            String tenantName = register.getOrganizationName() != null && !register.getOrganizationName().isBlank()
                    ? register.getOrganizationName()
                    : register.getFirstName() + " " + register.getLastName();

            tenantRequest.setTenantName(tenantName);
            tenantRequest.setSubscriptionPlan("BASIC");
            tenantRequest.setRoles(register.getRoles());
            tenantRequest.setParentId(register.getParentTenantId());

            UUID tenantId;
            try {
                // IMPORTANT: This call is external. If it succeeds but local User save fails, we MUST rollback TMS manually.
                HttpHeaders tmsHeaders = new HttpHeaders();
                tmsHeaders.setBearerAuth(JwtTokenProvider.issueInternalToken(
                        "auth-service", "tms-create-tenant", "tenant-management-service", 5));
                HttpEntity<CreateTenantRequest> tmsRequestEntity = new HttpEntity<>(tenantRequest, tmsHeaders);

                ResponseEntity<CreateTenantResponse> tenantResponse =
                        restTemplate.postForEntity(tenantServiceUrl, tmsRequestEntity, CreateTenantResponse.class);
                CreateTenantResponse tenantResponseBody = tenantResponse.getBody();

                if (!tenantResponse.getStatusCode().is2xxSuccessful() || tenantResponseBody == null) {
                    throw new RuntimeException("TMS responded with " + tenantResponse.getStatusCode());
                }
                tenantId = tenantResponseBody.getTenantId();
            } catch (Exception e) {
                log.error("TMS Call Failed", e);
                resp.put("statusCode", 503); resp.put("message", "Could not create organization. System busy."); return resp;
            }

            // ---------------------------------------------------------
            // STEP B: CREATE USER
            // ---------------------------------------------------------
            User user = new User();
            user.setFirstName(register.getFirstName());
            user.setLastName(register.getLastName());
            user.setUsername(register.getUsername());
            user.setEmail(register.getEmail());
            user.setPhoneNumber(register.getPhoneNumber());
            user.setPassword(passwordEncoder.encode(register.getPassword()));
            user.setIsAccountActive(true);
            user.setTenantId(tenantId);
            user.setGender(register.getGender());
            user.setDateOfBirth(register.getDateOfBirth());

            // Handle Roles (Prevent Duplicates)
            Set<Role> userRoles = new HashSet<>();
            List<String> rolesToAssign = register.getRoles() != null && !register.getRoles().isEmpty()
                    ? register.getRoles() : List.of("ROLE_USER");

            for (String roleName : rolesToAssign) {
                Role role = roleRepository.findByName(roleName)
                        .orElseGet(() -> roleRepository.save(new Role(roleName)));
                userRoles.add(role);
            }
            user.setRoles(userRoles);

            try {
                userRepository.save(user);
                log.info("User created successfully: {}", user.getUserId());
            } catch (Exception e) {
                log.error("User Save Failed. Initiating Compensation Transaction (Rollback Tenant: {})", tenantId, e);
                rollbackTenantCreation(tenantId); // Manual Compensation
                resp.put("statusCode", 500); resp.put("message", "Registration failed. Changes rolled back."); return resp;
            }

            // Cleanup Redis
            otpStore.delete(OtpStore.PURPOSE_SIGNUP, prospectId);
            redis.delete(regKey);
            removeIdentifierIndexes(prospectId, register);

            Map<String, Object> data = new HashMap<>();
            data.put("userId", user.getUserId());
            data.put("tenantId", user.getTenantId());
            data.put("organizationName", tenantName);

            resp.put("statusCode", 201);
            resp.put("message", "Registration successful!");
            resp.put("data", data);
            return resp;

        } catch (Exception e) {
            log.error("Verify OTP Error", e);
            resp.put("statusCode", 500); resp.put("message", "Internal Error: " + e.getMessage()); return resp;
        }
    }

    // ==================================================================================
    // 4. RESEND OTP
    // ==================================================================================
    public Map<String, Object> resendOtp(OtpResendRequest req) {
        Map<String, Object> resp = new HashMap<>();
        try {
            if (req.getIdentifier() == null) {
                resp.put("statusCode", 400); resp.put("message", "Identifier required"); return resp;
            }

            final String rawId = req.getIdentifier().trim();
            final String inferredType = inferTypeFromIdentifier(rawId);
            final String idxKey = indexKey(inferredType, "EMAIL".equals(inferredType) ? rawId.toLowerCase() : rawId);

            String prospectId = redis.opsForValue().get(idxKey);
            if (prospectId == null && looksLikeUuid(rawId)) prospectId = rawId.toLowerCase();

            if (prospectId == null) {
                resp.put("statusCode", 404); resp.put("message", "Pending registration not found."); return resp;
            }

            final String regKey = REG_KEY_FMT.formatted(prospectId);
            final String regJson = redis.opsForValue().get(regKey);
            if (regJson == null) {
                resp.put("statusCode", 404); resp.put("message", "Session expired."); return resp;
            }
            final RegisterDTO register = objectMapper.readValue(regJson, RegisterDTO.class);

            // Channel Logic
            final String requestedType = (req.getOtpChannel() == null) ? inferredType : req.getOtpChannel().trim().toUpperCase();
            final String outChannel;
            final String outIdentifier;

            if (requestedType.equals(inferredType)) {
                outChannel = inferredType;
                outIdentifier = normalizeIdentifier(inferredType, rawId, register);
            } else {
                if (!req.isAllowSwitch()) {
                    resp.put("statusCode", 400); resp.put("message", "Channel switch not allowed"); return resp;
                }
                if ("EMAIL".equals(requestedType)) {
                    outChannel = "EMAIL"; outIdentifier = register.getEmail();
                } else {
                    outChannel = "SMS"; outIdentifier = register.getPhoneNumber();
                }
            }

            // Rate Limit
            try { otpStore.ensureResendBudget(OtpStore.PURPOSE_SIGNUP, prospectId, maxOtpResendsPerHour); }
            catch (RuntimeException e) { resp.put("statusCode", 429); resp.put("message", "Too many attempts"); return resp; }

            // New OTP
            final String newOtp = otpStore.generateCode();
            Map<String, Object> extra = Map.of("prospectId", prospectId, "channel", outChannel, "createdAt", System.currentTimeMillis());

            otpStore.replaceOtp(OtpStore.PURPOSE_SIGNUP, prospectId, newOtp, extra, OTP_TTL);
            redis.opsForValue().set(regKey, regJson, OTP_TTL); // Refresh TTL

            sendOtpInternalJwt(prospectId, outChannel, outIdentifier, newOtp);

            resp.put("statusCode", 202);
            resp.put("message", "OTP resent");
            resp.put("data", Map.of("prospectId", prospectId));
            return resp;

        } catch (Exception e) {
            log.error("Resend Error", e);
            resp.put("statusCode", 500); resp.put("message", e.getMessage()); return resp;
        }
    }

    // ==================================================================================
    // 5. INTERNAL USER CREATION (Admin creates Employee)
    // ==================================================================================
    @Transactional // Ensures user + roles are saved atomically
    public Map<String, Object> createUserInternal(UserCreateDTO request, UUID adminTenantId) {
        Map<String, Object> response = new HashMap<>();
        try {
            if (userRepository.existsByUsername(request.getUsername())) throw new UserMessageException("Username taken");
            if (userRepository.existsByEmail(request.getEmail())) throw new UserMessageException("Email taken");

            User user = new User();
            user.setFirstName(request.getFirstName());
            user.setLastName(request.getLastName());
            user.setUsername(request.getUsername());
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setIsAccountActive(true);
            user.setTenantId(adminTenantId); // Force into Admin's Tenant

            Set<Role> userRoles = new HashSet<>();
            List<String> rolesToAssign = request.getRoles() != null ? request.getRoles() : List.of("ROLE_USER");

            for (String roleName : rolesToAssign) {
                Role role = roleRepository.findByName(roleName).orElseGet(() -> roleRepository.save(new Role(roleName)));
                userRoles.add(role);
            }
            user.setRoles(userRoles);

            userRepository.save(user);

            response.put("statusCode", 201);
            response.put("message", "User added to organization");
            response.put("userId", user.getUserId());
            return response;

        } catch (Exception e) {
            response.put("statusCode", 500);
            response.put("message", e.getMessage());
            return response;
        }
    }

    // ==================================================================================
    // 6. FETCH USERS BY TENANT ID
    // ==================================================================================
    @Transactional(readOnly = true)
    public List<UserSummaryDTO> findUsersByTenantId(UUID tenantId) {
        log.info("==== Fetching users for Tenant ID: {} ====", tenantId);

        List<User> users = userRepository.findByTenantId(tenantId);

        // THIS IS THE CRITICAL LOG:
        log.info("==== Found {} users in the database ====", users.size());

        return users.stream().map(user -> {
            UserSummaryDTO dto = new UserSummaryDTO();
            dto.setUserId(user.getUserId());
            dto.setUsername(user.getUsername());
            dto.setEmail(user.getEmail());

            // Null-safe role extraction to prevent 500 errors
            String roleName = "USER";
            if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                roleName = user.getRoles().iterator().next().getName();
            }
            dto.setAccessLevel(roleName);

            return dto;
        }).collect(Collectors.toList());
    }

    // ==================================================================================
    // 7. PASSWORD RESET
    // ==================================================================================

    /**
     * Always returns the same generic response whether or not the identifier
     * matches a real account - a distinguishable response here would let a
     * caller enumerate valid usernames/emails by probing this endpoint.
     */
    public Map<String, Object> initiatePasswordReset(PasswordResetInitDTO request) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("statusCode", 200);
        resp.put("message", "If an account exists for that identifier, a password reset code has been sent.");

        String identifier = request.getIdentifier().trim();
        Optional<User> userOpt = userRepository.findByUsernameOrEmail(identifier);
        if (userOpt.isEmpty()) {
            log.info("Password reset requested for an identifier with no matching account");
            return resp;
        }
        User user = userOpt.get();

        String otp = otpStore.generateCode();
        otpStore.saveNew(OtpStore.PURPOSE_PASSWORD_RESET, identifier, otp,
                Map.of("userId", user.getUserId().toString()), PASSWORD_RESET_OTP_TTL);

        String channel = identifier.contains("@") ? "EMAIL" : "SMS";
        sendOtpInternalJwt(user.getUserId().toString(), channel, identifier, otp, "Reset your password");

        return resp;
    }

    public Map<String, Object> confirmPasswordReset(PasswordResetConfirmDTO request) {
        Map<String, Object> resp = new HashMap<>();
        String identifier = request.getIdentifier().trim();

        // Same enforcement shape as registration's OTP verify - capped at
        // maxOtpAttempts wrong guesses before the code must be re-requested.
        Map<String, Object> otpRecord = otpStore.get(OtpStore.PURPOSE_PASSWORD_RESET, identifier);
        int attemptsSoFar = otpRecord == null ? 0 : ((Number) otpRecord.getOrDefault("attempts", 0)).intValue();
        if (attemptsSoFar >= maxOtpAttempts) {
            resp.put("statusCode", 429);
            resp.put("message", "Too many incorrect attempts. Please request a new code.");
            return resp;
        }

        if (!otpStore.verify(OtpStore.PURPOSE_PASSWORD_RESET, identifier, request.getOtp())) {
            otpStore.incrementAttempts(OtpStore.PURPOSE_PASSWORD_RESET, identifier);
            resp.put("statusCode", 400);
            resp.put("message", "Invalid or expired code.");
            return resp;
        }

        Optional<User> userOpt = userRepository.findByUsernameOrEmail(identifier);
        if (userOpt.isEmpty()) {
            // OTP verified but the account is gone (deleted mid-flow) - stay generic.
            resp.put("statusCode", 400);
            resp.put("message", "Invalid or expired code.");
            return resp;
        }
        User user = userOpt.get();

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        otpStore.delete(OtpStore.PURPOSE_PASSWORD_RESET, identifier);

        // A password reset means any previously-issued session (and refresh
        // token) should stop working - if the reset was prompted by a
        // compromised account, this is what actually locks the attacker out.
        refreshTokenService.revokeAllForUser(user);

        resp.put("statusCode", 200);
        resp.put("message", "Password has been reset. Please log in again.");
        return resp;
    }

    // ==================================================================================
    // HELPERS
    // ==================================================================================

    private void rollbackTenantCreation(UUID tenantId) {
        try {
            String rollbackUrl = tenantServiceUrl.endsWith("/") ? tenantServiceUrl + "internal/" + tenantId : tenantServiceUrl + "/internal/" + tenantId;

            HttpHeaders tmsHeaders = new HttpHeaders();
            tmsHeaders.setBearerAuth(JwtTokenProvider.issueInternalToken(
                    "auth-service", "tms-rollback-tenant", "tenant-management-service", 5));
            HttpEntity<Void> rollbackEntity = new HttpEntity<>(tmsHeaders);

            restTemplate.exchange(rollbackUrl, HttpMethod.DELETE, rollbackEntity, Void.class);
            log.info("Rollback successful for tenant: {}", tenantId);
        } catch (Exception ex) {
            log.error("FATAL: Rollback failed for tenant {}", tenantId, ex);
        }
    }

    private boolean sendOtpInternalJwt(String prospectId, String channel, String identifier, String otp) {
        return sendOtpInternalJwt(prospectId, channel, identifier, otp, "Verify your Account");
    }

    private boolean sendOtpInternalJwt(String prospectId, String channel, String identifier, String otp, String emailSubject) {
        try {
            String token = JwtTokenProvider.issueInternalToken("auth-service", prospectId, 10);
            String bearer = "Bearer " + token;

            Map<String, Object> payloadData = new HashMap<>();
            if ("SMS".equalsIgnoreCase(channel)) {
                payloadData.put("phoneNumber", identifier);
                payloadData.put("content", "Your OTP is " + otp);
            } else {
                payloadData.put("to", identifier);
                payloadData.put("subject", emailSubject);
                payloadData.put("body", "<h1>" + otp + "</h1>");
                payloadData.put("isHtml", true);
            }

            NotificationRequest request = NotificationRequest.builder()
                    .type(NotificationType.valueOf(channel.toUpperCase()))
                    .sourceApp("auth-service")
                    .priority(BaseRequest.Priority.HIGH)
                    .payload(payloadData)
                    .timestamp(System.currentTimeMillis())
                    .build();

            // Try Feign
            try {
                Map<String, Object> requestMap = objectMapper.convertValue(request, new TypeReference<>() {});
                ResponseEntity<BaseResponse<NotificationResponse>> res = notificationClient.sendInternalPreReg(bearer, prospectId, requestMap);
                BaseResponse<NotificationResponse> resBody = res.getBody();
                if (resBody != null && resBody.isSuccess()) return true;
            } catch (Exception e) {
                log.warn("Feign failed, switching to fallback: {}", e.getMessage());
            }

            // Fallback RestTemplate
            String url = notificationBaseUrl + "/api/notifications/internal/send";
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.add("X-Prospect-ID", prospectId);
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<NotificationRequest> entity = new HttpEntity<>(request, headers);

            return restTemplate.postForEntity(url, entity, String.class).getStatusCode().is2xxSuccessful();

        } catch (Exception e) {
            log.error("Send OTP Error", e);
            return false;
        }
    }

    // Redis Helpers
    private void saveOtpAndPending(String prospectId, String otp, RegisterDTO request) throws Exception {
        Map<String, Object> extra = Map.of("prospectId", prospectId);
        otpStore.saveNew(OtpStore.PURPOSE_SIGNUP, prospectId, otp, extra, OTP_TTL);
        redis.opsForValue().set(REG_KEY_FMT.formatted(prospectId), objectMapper.writeValueAsString(request), OTP_TTL);
        if (request.getEmail() != null) redis.opsForValue().set(indexKey("EMAIL", request.getEmail()), prospectId, OTP_TTL);
        if (request.getPhoneNumber() != null) redis.opsForValue().set(indexKey("SMS", request.getPhoneNumber()), prospectId, OTP_TTL);
    }

    private void removeIdentifierIndexes(String prospectId, RegisterDTO request) {
        if (request.getEmail() != null) redis.delete(indexKey("EMAIL", request.getEmail()));
        if (request.getPhoneNumber() != null) redis.delete(indexKey("SMS", request.getPhoneNumber()));
    }

    private String indexKey(String type, String id) {
        return IDX_KEY_FMT.formatted(type.toUpperCase(Locale.ROOT), id.trim().toLowerCase(Locale.ROOT));
    }

    private String normalizeIdentifier(String type, String provided, RegisterDTO reg) {
        if ("EMAIL".equalsIgnoreCase(type)) return reg.getEmail().trim().toLowerCase();
        return String.valueOf(reg.getPhoneNumber());
    }

    private String resolveChannel(String requested, String phone, String email) {
        if ("SMS".equalsIgnoreCase(requested) && phone != null && !phone.isBlank()) return "SMS";
        return "EMAIL";
    }

    private String inferTypeFromIdentifier(String id) { return id.contains("@") ? "EMAIL" : "SMS"; }

    private boolean looksLikeUuid(String s) {
        try { UUID.fromString(s); return true; } catch (Exception e) { return false; }
    }
}

