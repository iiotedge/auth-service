package com.iotmining.services.auth.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotmining.common.base.notifications.dto.BaseResponse;
import com.iotmining.common.base.notifications.dto.NotificationResponse;
import com.iotmining.services.auth.clients.NotificationClient;
import com.iotmining.services.auth.dto.*;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.exceptions.UserMessageException;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Log4j2
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final UserLoginDataService userLoginDataService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final RestTemplate restTemplate;                 // TMS + fallback to notifications
    private final NotificationClient notificationClient;     // Feign to notification-service
    private final StringRedisTemplate redis;                 // Redis for pending-reg + indexes
    private final ObjectMapper objectMapper;

    private final OtpStore otpStore;

    @Value("${tenant.service.url}")
    private String tenantServiceUrl;

    @Value("${notification.service.url:http://localhost:8087}")
    private String notificationBaseUrl;

    // Redis keys / TTL
    private static final String REG_KEY_FMT = "reg:prospect:%s";
    private static final String IDX_KEY_FMT = "reg:index:%s:%s"; // type,email|phone -> prospectId
    private static final Duration OTP_TTL = Duration.ofMinutes(5);

    // ================= LOGIN =================
    public Map<String, Object> verify(UserCredentialDTO request) {
        Map<String, Object> response = new HashMap<>();
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            if (!authentication.isAuthenticated()) {
                response.put("message", "Bad credentials");
                response.put("statusCode", 401);
                response.put("data", null);
                return response;
            }

            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            if (!userPrincipal.isEnabled()) {
                throw new UserMessageException("Account is not active");
            }

            List<String> roles = userPrincipal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            UserLoginDataDTO userLoginData = JwtTokenProvider.generateToken(userPrincipal, roles);
            User user = userPrincipal.getUser();
            userLoginData.setUser(user);
            userLoginData.setId(user.getUserId());
            userLoginData.setIsUserLoggedIn(true);

            AuthResponseDTO authResponseDTO = new AuthResponseDTO();
            authResponseDTO.setAccessToken(userLoginData.getConfirmationToken());
            authResponseDTO.setIsAccountActive(true);

            userLoginDataService.addUserAsyncLoginData(userLoginData);

            response.put("message", "Login successful");
            response.put("statusCode", 200);
            response.put("data", authResponseDTO);
            return response;

        } catch (UserMessageException e) {
            response.put("message", e.getMessage());
            response.put("statusCode", 401);
            response.put("data", null);
            return response;
        } catch (BadCredentialsException e) {
            response.put("message", "Bad credentials");
            response.put("statusCode", 401);
            response.put("data", null);
            return response;
        } catch (RuntimeException e) {
            response.put("message", "Internal Server Error: " + e.getMessage());
            response.put("statusCode", 500);
            response.put("data", null);
            return response;
        }
    }

    // ============== REGISTRATION: INIT (OTP) ==============
    public Map<String, Object> registerInit(RegisterDTO request) {
        Map<String, Object> resp = new HashMap<>();
        try {
            if (request.getRoles() != null && request.getRoles().contains("ROLE_SUPER_ADMIN")) {
                throw new UserMessageException("You are not authorized to create a Super Admin account, Thanks.");
            }

            if (userRepository.existsByUsername(request.getUsername())) {
                resp.put("statusCode", 409);
                resp.put("message", "Username already exists.");
                resp.put("data", null);
                return resp;
            }

            final String email = request.getEmail();
            final String phone = request.getPhoneNumber() == null ? null : String.valueOf(request.getPhoneNumber());
            final String resolvedChannel = resolveChannel(request.getOtpChannel(), phone, email);

            final UUID prospectId = UUID.randomUUID();
            final String pId = prospectId.toString().toLowerCase(Locale.ROOT);
            final String otp = otpStore.generateCode();

            // Persist OTP (hashed) + pending registration + identifier indexes
            saveOtpAndPending(pId, otp, request);

            boolean delivered = sendOtpAccordingToMode(prospectId, resolvedChannel, request, otp);
            if (!delivered) {
                resp.put("statusCode", 500);
                resp.put("message", "Failed to deliver OTP");
                resp.put("data", null);
                return resp;
            }

            Map<String, Object> data = new HashMap<>();
            data.put("prospectId", pId);
            data.put("otpChannel", resolvedChannel);

            resp.put("statusCode", 202);
            resp.put("message", "OTP sent");
            resp.put("data", data);
            return resp;

        } catch (UserMessageException e) {
            resp.put("statusCode", 400);
            resp.put("message", "Register failed! " + e.getMessage());
            resp.put("data", null);
            return resp;
        } catch (Exception e) {
            log.warn("registerInit error: {}", e.getMessage(), e);
            resp.put("statusCode", 500);
            resp.put("message", "Internal Error during registration: " + e.getMessage());
            resp.put("data", null);
            return resp;
        }
    }

    // ============== REGISTRATION: VERIFY OTP ==============
    public Map<String, Object> verifyOtp(OtpVerifyRequest req) {
        Map<String, Object> resp = new HashMap<>();
        try {
            if (req.getIdentifier() == null || req.getIdentifier().isBlank()) {
                resp.put("statusCode", 400);
                resp.put("message", "identifier is required");
                resp.put("data", null);
                return resp;
            }
            if (req.getType() == null || req.getType().isBlank()) {
                resp.put("statusCode", 400);
                resp.put("message", "type is required (SMS|EMAIL)");
                resp.put("data", null);
                return resp;
            }

            final String type = req.getType().trim().toUpperCase(Locale.ROOT); // "SMS" or "EMAIL"
            final String rawId = req.getIdentifier().trim();
            final String normalizedId = "EMAIL".equals(type) ? rawId.toLowerCase(Locale.ROOT) : rawId;

            // 1) Resolve prospectId from the index (email/phone) OR treat identifier as a raw prospectId (UUID)
            String prospectId = redis.opsForValue().get(indexKey(type, normalizedId));
            if (prospectId == null && looksLikeUuid(rawId)) {
                prospectId = rawId.toLowerCase(Locale.ROOT);
            }
            if (prospectId == null) {
                resp.put("statusCode", 404);
                resp.put("message", "Pending user not found for identifier");
                resp.put("data", null);
                return resp;
            }

            // 2) Verify OTP using OtpStore (hashed)
            boolean ok = otpStore.verify(prospectId, req.getOtp());
            if (!ok) {
                resp.put("statusCode", 400);
                resp.put("message", "Invalid or expired OTP.");
                resp.put("data", null);
                return resp;
            }

            // 3) Load pending registration
            final String regKey = REG_KEY_FMT.formatted(prospectId);
            final String regJson = redis.opsForValue().get(regKey);
            if (regJson == null) {
                resp.put("statusCode", 404);
                resp.put("message", "Pending user not found.");
                resp.put("data", null);
                return resp;
            }
            final RegisterDTO register = objectMapper.readValue(regJson, RegisterDTO.class);

            // === Create tenant via TMS ===
            CreateTenantRequest tenantRequest = new CreateTenantRequest();
            tenantRequest.setTenantName(register.getFirstName() + " " + register.getLastName());
            tenantRequest.setSubscriptionPlan("BASIC");
            tenantRequest.setRoles(register.getRoles());
            tenantRequest.setParentId(register.getParentTenantId());

            ResponseEntity<CreateTenantResponse> tenantResponse =
                    restTemplate.postForEntity(tenantServiceUrl, tenantRequest, CreateTenantResponse.class);

            if (tenantResponse.getBody() == null || tenantResponse.getBody().getTenantId() == null) {
                throw new RuntimeException("Failed to create tenant for user: " + register.getUsername());
            }
            UUID tenantId = tenantResponse.getBody().getTenantId();

            // === Persist user ===
            User user = new User();
            user.setFirstName(register.getFirstName());
            user.setLastName(register.getLastName());
            user.setGender(register.getGender());
            user.setDateOfBirth(register.getDateOfBirth());
            user.setIsAccountActive(!(register.getRoles() != null && register.getRoles().contains("ROLE_ADMIN")));
            user.setEmail(register.getEmail());
            user.setPassword(passwordEncoder.encode(register.getPassword()));
            user.setPhoneNumber(register.getPhoneNumber());
            user.setUsername(register.getUsername());
            user.setTenantId(tenantId);

            userRepository.save(user);

            // === Cleanup ===
            otpStore.delete(prospectId);
            redis.delete(regKey);
            removeIdentifierIndexes(prospectId, register); // removes both EMAIL and SMS index keys if they exist

            Map<String, Object> data = new HashMap<>();
            data.put("userId", user.getUserId());
            data.put("tenantId", user.getTenantId());

            resp.put("statusCode", 201);
            resp.put("message", "User created");
            resp.put("data", data);
            return resp;

        } catch (DataIntegrityViolationException e) {
            resp.put("statusCode", 409);
            resp.put("message", "Username already exists.");
            resp.put("data", null);
            return resp;
        } catch (Exception e) {
            log.warn("verifyOtp error: {}", e.getMessage(), e);
            resp.put("statusCode", 500);
            resp.put("message", "Internal Error during OTP verification: " + e.getMessage());
            resp.put("data", null);
            return resp;
        }
    }

    // ============== REGISTRATION: RESEND OTP ==============
    public Map<String, Object> resendOtp(OtpResendRequest req) {
        Map<String, Object> resp = new HashMap<>();
        try {
            if (req.getIdentifier() == null || req.getIdentifier().isBlank()) {
                resp.put("statusCode", 400);
                resp.put("message", "identifier is required");
                resp.put("data", null);
                return resp;
            }

            final String rawId = req.getIdentifier().trim();
            final String inferredType = inferTypeFromIdentifier(rawId); // EMAIL if contains '@' else SMS
            final String idxKey = indexKey(inferredType, "EMAIL".equals(inferredType) ? rawId.toLowerCase(Locale.ROOT) : rawId);

            // Resolve prospectId from index OR from raw UUID
            String prospectId = redis.opsForValue().get(idxKey);
            if (prospectId == null && looksLikeUuid(rawId)) {
                prospectId = rawId.toLowerCase(Locale.ROOT);
            }
            if (prospectId == null) {
                resp.put("statusCode", 404);
                resp.put("message", "Pending user not found for identifier");
                resp.put("data", null);
                return resp;
            }

            // Load pending registration
            final String regKey = REG_KEY_FMT.formatted(prospectId);
            final String regJson = redis.opsForValue().get(regKey);
            if (regJson == null) {
                resp.put("statusCode", 404);
                resp.put("message", "Pending user not found.");
                resp.put("data", null);
                return resp;
            }
            final RegisterDTO register = objectMapper.readValue(regJson, RegisterDTO.class);

            // Determine outbound channel/identifier
            final String requestedType = (req.getOtpChannel() == null)
                    ? inferredType
                    : req.getOtpChannel().trim().toUpperCase(Locale.ROOT);

            final String outChannel;
            final String outIdentifier;

            if (requestedType.equals(inferredType)) {
                outChannel = inferredType;
                outIdentifier = normalizeIdentifier(inferredType, rawId, register);
            } else {
                if (!req.isAllowSwitch()) {
                    resp.put("statusCode", 400);
                    resp.put("message", "Switching channel requires allowSwitch=true");
                    resp.put("data", null);
                    return resp;
                }
                if ("EMAIL".equals(requestedType)) {
                    if (register.getEmail() == null || register.getEmail().isBlank()) {
                        resp.put("statusCode", 400);
                        resp.put("message", "Email not present on pending registration");
                        resp.put("data", null);
                        return resp;
                    }
                    outChannel = "EMAIL";
                    outIdentifier = register.getEmail().trim().toLowerCase(Locale.ROOT);
                } else if ("SMS".equals(requestedType)) {
                    if (register.getPhoneNumber() == null) {
                        resp.put("statusCode", 400);
                        resp.put("message", "Phone number not present on pending registration");
                        resp.put("data", null);
                        return resp;
                    }
                    outChannel = "SMS";
                    outIdentifier = String.valueOf(register.getPhoneNumber());
                } else {
                    resp.put("statusCode", 400);
                    resp.put("message", "type must be either SMS or EMAIL");
                    resp.put("data", null);
                    return resp;
                }
            }

            // Optional: enforce resend budget per prospect (per-hour cap)
            try {
                otpStore.ensureResendBudget(prospectId, 5);
            } catch (RuntimeException budgetEx) {
                resp.put("statusCode", 429);
                resp.put("message", "Too many OTP resends. Try again later.");
                resp.put("data", null);
                return resp;
            }

            // Replace OTP (hashed) and refresh TTLs for reg + indexes
            final String newOtp = otpStore.generateCode();
            Map<String, Object> extra = Map.of(
                    "prospectId", prospectId,
                    "channel", outChannel,
                    "createdAt", System.currentTimeMillis()
            );
            otpStore.replaceOtp(prospectId, newOtp, extra, OTP_TTL);
            redis.opsForValue().set(regKey, regJson, OTP_TTL);
            refreshIdentifierIndexes(prospectId, register);

            boolean delivered = sendOtpInternalJwt(prospectId, outChannel, outIdentifier, newOtp);
            if (!delivered) {
                resp.put("statusCode", 500);
                resp.put("message", "Failed to deliver OTP");
                resp.put("data", null);
                return resp;
            }

            Map<String, Object> data = new HashMap<>();
            data.put("prospectId", prospectId);
            data.put("otpChannel", outChannel);

            resp.put("statusCode", 202);
            resp.put("message", "OTP resent");
            resp.put("data", data);
            return resp;

        } catch (Exception e) {
            log.warn("resendOtp error: {}", e.getMessage(), e);
            resp.put("statusCode", 500);
            resp.put("message", "Internal Error during resend: " + e.getMessage());
            resp.put("data", null);
            return resp;
        }
    }

    // ================= helpers =================

    private void saveOtpAndPending(String prospectId, String otp, RegisterDTO request) {
        try {
            // 1) Store hashed OTP via OtpStore
            Map<String, Object> extra = new HashMap<>();
            extra.put("prospectId", prospectId);
            extra.put("channel", resolveChannel(request.getOtpChannel(),
                    request.getPhoneNumber() == null ? null : String.valueOf(request.getPhoneNumber()),
                    request.getEmail()));
            extra.put("createdAt", System.currentTimeMillis());
            otpStore.saveNew(prospectId, otp, extra, OTP_TTL);

            // 2) Store pending registration JSON
            redis.opsForValue().set(REG_KEY_FMT.formatted(prospectId), toJson(request), OTP_TTL);

            // 3) Create identifier indexes (both if present)
            indexProspectIdentifiers(prospectId, request);

        } catch (Exception e) {
            throw new RuntimeException("Failed to persist OTP state in Redis", e);
        }
    }

    private void indexProspectIdentifiers(String prospectId, RegisterDTO request) {
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
            redis.opsForValue().set(indexKey("EMAIL", email), prospectId, OTP_TTL);
        }
        if (request.getPhoneNumber() != null) {
            String phone = String.valueOf(request.getPhoneNumber());
            redis.opsForValue().set(indexKey("SMS", phone), prospectId, OTP_TTL);
        }
    }

    private void refreshIdentifierIndexes(String prospectId, RegisterDTO request) {
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
            redis.opsForValue().set(indexKey("EMAIL", email), prospectId, OTP_TTL);
        }
        if (request.getPhoneNumber() != null) {
            String phone = String.valueOf(request.getPhoneNumber());
            redis.opsForValue().set(indexKey("SMS", phone), prospectId, OTP_TTL);
        }
    }

    private void removeIdentifierIndexes(String prospectId, RegisterDTO request) {
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
            redis.delete(indexKey("EMAIL", email));
        }
        if (request.getPhoneNumber() != null) {
            String phone = String.valueOf(request.getPhoneNumber());
            redis.delete(indexKey("SMS", phone));
        }
    }

    private String indexKey(String type, String identifier) {
        String id = "EMAIL".equalsIgnoreCase(type)
                ? identifier.trim().toLowerCase(Locale.ROOT)
                : identifier.trim();
        return IDX_KEY_FMT.formatted(type.toUpperCase(Locale.ROOT), id);
    }

    private String inferTypeFromIdentifier(String identifier) {
        return identifier.contains("@") ? "EMAIL" : "SMS";
    }

    private String normalizeIdentifier(String type, String provided, RegisterDTO reg) {
        if ("EMAIL".equalsIgnoreCase(type)) {
            return reg.getEmail() != null ? reg.getEmail().trim().toLowerCase(Locale.ROOT) : provided.trim().toLowerCase(Locale.ROOT);
        } else {
            return reg.getPhoneNumber() != null ? String.valueOf(reg.getPhoneNumber()) : provided.trim();
        }
    }

    private String resolveChannel(String requested, String phone, String email) {
        String req = requested == null ? "AUTO" : requested.trim().toUpperCase(Locale.ROOT);

        if ("EMAIL".equals(req)) return "EMAIL";
        if ("SMS".equals(req)) return "SMS";
        if ("BOTH".equals(req)) return "BOTH";

        // AUTO: if both present -> BOTH
        if (email != null && !email.isBlank() && phone != null && !phone.isBlank()) return "BOTH";
        if (email != null && !email.isBlank()) return "EMAIL";
        if (phone != null && !phone.isBlank()) return "SMS";
        return "EMAIL"; // fallback
    }

    private boolean sendOtpAccordingToMode(UUID prospectId, String channel, RegisterDTO request, String otp) {
        String email = request.getEmail();
        String phone = request.getPhoneNumber() == null ? null : String.valueOf(request.getPhoneNumber());

        boolean ok = false;
        if ("BOTH".equals(channel)) {
            if (email != null && !email.isBlank()) {
                ok |= sendOtpInternalJwt(prospectId.toString(), "EMAIL", email, otp);
            }
            if (phone != null && !phone.isBlank()) {
                ok |= sendOtpInternalJwt(prospectId.toString(), "SMS", phone, otp);
            }
        } else if ("EMAIL".equals(channel)) {
            if (email != null && !email.isBlank()) {
                ok = sendOtpInternalJwt(prospectId.toString(), "EMAIL", email, otp);
            }
        } else {
            if (phone != null && !phone.isBlank()) {
                ok = sendOtpInternalJwt(prospectId.toString(), "SMS", phone, otp);
            }
        }
        return ok;
    }

    /**
     * Try Feign first; if for any reason the Authorization header doesn't make it through,
     * fallback to RestTemplate with explicit headers.
     */
    private boolean sendOtpInternalJwt(String prospectId, String channel, String identifier, String otp) {
        try {
            String token = JwtTokenProvider.issueInternalToken("auth-service", prospectId, 10);
            String bearer = "Bearer " + token;

            Map<String, Object> body = new HashMap<>();
            body.put("type", channel);                // "EMAIL" | "SMS"
            body.put("sourceApp", "auth-service");
            body.put("priority", "HIGH");
            body.put("retryCount", 0);
            body.put("timestamp", System.currentTimeMillis());

            Map<String, Object> payload = new HashMap<>();
            if ("SMS".equalsIgnoreCase(channel)) {
                payload.put("phoneNumber", identifier);
                payload.put("content", "Your OTP is " + otp + ". It expires in 5 minutes.");
            } else {
                payload.put("to", identifier);
                payload.put("subject", "Your OTP Code");
                payload.put("message", "Your OTP is " + otp + ". It expires in 5 minutes.");
            }
            body.put("payload", payload);

            // --- Attempt via FEIGN ---
            try {
                ResponseEntity<BaseResponse<NotificationResponse>> res =
                        notificationClient.sendInternalPreReg(bearer, prospectId, body);

                if (res.getBody() != null && res.getBody().isSuccess() && res.getBody().isDelivered()) {
                    return true;
                }
                log.warn("Feign call to notification-service returned non-success or not delivered: {}", res.getStatusCode());
            } catch (Exception feignEx) {
                log.warn("Feign internal-send failed (will fallback to RestTemplate): {}", feignEx.getMessage());
            }

            // --- Fallback via RESTTEMPLATE (headers set explicitly) ---
            String url = notificationBaseUrl + "/api/notifications/internal/send";
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.add("X-Prospect-ID", prospectId);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<String> rtRes = restTemplate.postForEntity(url, entity, String.class);

            if (!rtRes.getStatusCode().is2xxSuccessful()) {
                log.warn("RestTemplate internal-send non-2xx: {}", rtRes.getStatusCode());
                return false;
            }

            BaseResponse<NotificationResponse> parsed =
                    objectMapper.readValue(rtRes.getBody(), new TypeReference<BaseResponse<NotificationResponse>>() {});
            return parsed != null && parsed.isSuccess() && parsed.isDelivered();

        } catch (HttpStatusCodeException sce) {
            log.warn("sendOtpInternalJwt HTTP error: {} body={}", sce.getStatusCode(), sce.getResponseBodyAsString());
            return false;
        } catch (Exception e) {
            log.warn("sendOtpInternalJwt failed: {}", e.getMessage(), e);
            return false;
        }
    }

    private boolean looksLikeUuid(String s) {
        try {
            UUID.fromString(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String toJson(Object o) {
        try {
            return objectMapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String generateOtp(int length) {
        // kept for compatibility if you ever need it elsewhere (OtpStore.generateCode is used above)
        String digits = "0123456789";
        Random r = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append(digits.charAt(r.nextInt(digits.length())));
        return sb.toString();
    }
}





//package com.iotmining.services.auth.services;
//
//import java.util.*;
//import java.util.stream.Collectors;
//
//import com.iotmining.services.auth.dto.*;
//import com.iotmining.services.auth.entity.Role;
//import com.iotmining.services.auth.entity.User;
//import com.iotmining.services.auth.exceptions.UserMessageException;
//import com.iotmining.services.auth.repository.UserRepository;
//import com.iotmining.services.auth.security.UserPrincipal;
//import com.iotmining.services.auth.util.JwtTokenProvider;
//import lombok.RequiredArgsConstructor;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.dao.DataIntegrityViolationException;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.RestTemplate;
//
//@Service
//
//public class UserService {
//
//    private final AuthenticationManager authenticationManager;
//    private final UserLoginDataService userLoginDataService;
//    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final RestTemplate restTemplate;
//
//    @Value("${tenant.service.url}")
//    private String tenantServiceUrl;
//
//    private final Map<String, Object> response = new HashMap<>();
//
//    public UserService(AuthenticationManager authenticationManager, UserLoginDataService userLoginDataService, UserRepository userRepository, PasswordEncoder passwordEncoder, RestTemplate restTemplate) {
//        this.authenticationManager = authenticationManager;
//        this.userLoginDataService = userLoginDataService;
//        this.userRepository = userRepository;
//        this.passwordEncoder = passwordEncoder;
//        this.restTemplate = restTemplate;
//    }
//
//    public Map<String, Object> verify(UserCredentialDTO request) {
//        try {
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
//
//            if (authentication.isAuthenticated()) {
//                AuthResponseDTO authResponseDTO = new AuthResponseDTO();
//
//                UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
//
//                if (!userPrincipal.isEnabled()) {
//                    authResponseDTO.setAccessToken(null);
//                    authResponseDTO.setIsAccountActive(false);
//                    throw new UserMessageException("Account is not active");
//                }
//
//                List<String> roles = userPrincipal.getAuthorities().stream()
//                        .map(GrantedAuthority::getAuthority)
//                        .collect(Collectors.toList());
//
//                UserLoginDataDTO userLoginData = JwtTokenProvider.generateToken(userPrincipal, roles);
//                User user = userPrincipal.getUser();
//                userLoginData.setUser(user);
//                userLoginData.setId(user.getUserId());
//                userLoginData.setIsUserLoggedIn(true);
//
//                authResponseDTO.setAccessToken(userLoginData.getConfirmationToken());
//                authResponseDTO.setIsAccountActive(true);
//
//                userLoginDataService.addUserAsyncLoginData(userLoginData);
//
//                response.put("message", "Login successful");
//                response.put("statusCode", 200);
//                response.put("data", authResponseDTO);
//
//                return response;
//            }
//            response.put("message", "Bad credentials");
//            response.put("statusCode", 401);
//            response.put("data", null);
//            return response;
//
//        } catch (UserMessageException e) {
//            response.put("message", e.getMessage());
//            response.put("statusCode", 401);
//            response.put("data", null);
//            return response;
//        } catch (BadCredentialsException e) {
//            response.put("message", "Bad credentials");
//            response.put("statusCode", 401);
//            response.put("data", null);
//            return response;
//        } catch (RuntimeException e) {
//            response.put("message", "Internal Server Error: " + e.getMessage());
//            response.put("statusCode", 500);
//            response.put("data", null);
//            return response;
//        }
//    }
//
////    public Map<String, Object> registerUser(RegisterDTO request) {
////
////        try {
////            if (request.getRoles().contains("ROLE_SUPER_ADMIN")) {
////                throw new UserMessageException("You are not authorized to create a Super Admin account, Thanks.");
////            }
////
////            User user = new User();
////            user.setFirstName(request.getFirstName());
////            user.setLastName(request.getLastName());
////            user.setGender(request.getGender());
////            user.setDateOfBirth(request.getDateOfBirth());
////            user.setIsAccountActive(!request.getRoles().contains("ROLE_ADMIN"));
////            user.setEmail(request.getEmail());
////            user.setPassword(passwordEncoder.encode(request.getPassword()));
////            user.setPhoneNumber(request.getPhoneNumber());
////            user.setUsername(request.getUsername());
//////            // ✅ Fetch existing Roles or create if not exists
//////            Set<Role> userRoles = request.getRoles()
//////                    .stream()
//////                    .map(roleName -> roleRepository.findByRoleName(roleName)
//////                            .orElseGet(() -> roleRepository.save(new Role(roleName))))
//////                    .collect(Collectors.toSet());
////
//////            user.setRoles(request.getRoles().stream().map(Role::new).collect(Collectors.toSet()));
////
////            // Step 1: Save User first
//////            User savedUser = userRepository.save(user);
////
////            // Step 2: Call Tenant Management Service to create tenant
////            CreateTenantRequest tenantRequest = new CreateTenantRequest(
////                    user.getUsername(),
////                    "BASIC" // default subscription plan
////            );
////
////            ResponseEntity<CreateTenantResponse> tenantResponse = restTemplate.postForEntity(
////                    tenantServiceUrl,
////                    tenantRequest,
////                    CreateTenantResponse.class
////            );
////
////            if (tenantResponse.getStatusCode().is2xxSuccessful() && tenantResponse.getBody() != null) {
////                UUID tenantId = tenantResponse.getBody().getTenantId();
////                user.setTenantId(tenantId);
////                userRepository.save(user); // Update with tenant ID
////            } else {
////                throw new RuntimeException("Failed to create tenant for user: " + user.getUsername());
////            }
////
////            response.put("message", "Register successful!");
////            response.put("statusCode", 201);
////            response.put("data", user);
////            return response;
////
////        } catch (DataIntegrityViolationException e) {
////            response.put("message", "Username already exists.");
////            response.put("statusCode", 409);
////            response.put("data", null);
////            return response;
////        } catch (UserMessageException e) {
////            response.put("message", "Register failed!, " + e.getMessage());
////            response.put("statusCode", 400);
////            response.put("data", null);
////            return response;
////        } catch (Exception e) {
////            response.put("message", "Internal Error during registration: " + e.getMessage());
////            response.put("statusCode", 500);
////            response.put("data", null);
////            return response;
////        }
////    }
//    public Map<String, Object> registerUser(RegisterDTO request) {
//        Map<String, Object> response = new HashMap<>();
//        try {
//            if (request.getRoles().contains("ROLE_SUPER_ADMIN")) {
//                throw new UserMessageException("You are not authorized to create a Super Admin account, Thanks.");
//            }
//
//            // ---- CHECK FOR DUPLICATE FIRST! ----
//            if (userRepository.existsByUsername(request.getUsername())) {
//                response.put("message", "Username already exists.");
//                response.put("statusCode", 409);
//                response.put("data", null);
//                return response;
//            }
////            if (userRepository.existsByEmail(request.getEmail())) {
////                response.put("message", "Email already exists.");
////                response.put("statusCode", 409);
////                response.put("data", null);
////                return response;
////            }
//
//            // Step 1: Save User basic info (but don't persist yet)
//            User user = new User();
//            user.setFirstName(request.getFirstName());
//            user.setLastName(request.getLastName());
//            user.setGender(request.getGender());
//            user.setDateOfBirth(request.getDateOfBirth());
//            user.setIsAccountActive(!request.getRoles().contains("ROLE_ADMIN"));
//            user.setEmail(request.getEmail());
//            user.setPassword(passwordEncoder.encode(request.getPassword()));
//            user.setPhoneNumber(request.getPhoneNumber());
//            user.setUsername(request.getUsername());
//
//            UUID parentId = request.getParentTenantId();
//
//            // Step 2: Now call TMS, since we know the user is unique!
//            CreateTenantRequest tenantRequest = new CreateTenantRequest();
//            tenantRequest.setTenantName(user.getFirstName() + " " + user.getLastName());
//            tenantRequest.setSubscriptionPlan("BASIC");
//            tenantRequest.setRoles(request.getRoles());
//            tenantRequest.setParentId(parentId);
//
//            ResponseEntity<CreateTenantResponse> tenantResponse = restTemplate.postForEntity(
//                    tenantServiceUrl,
//                    tenantRequest,
//                    CreateTenantResponse.class
//            );
//
//            if (tenantResponse.getStatusCode().is2xxSuccessful() && tenantResponse.getBody() != null) {
//                UUID tenantId = tenantResponse.getBody().getTenantId();
//                user.setTenantId(tenantId);
//                userRepository.save(user);
//            } else {
//                throw new RuntimeException("Failed to create tenant for user: " + user.getUsername());
//            }
//
//            response.put("message", "Register successful!");
//            response.put("statusCode", 201);
//            response.put("data", user);
//            return response;
//
//        } catch (UserMessageException e) {
//            response.put("message", "Register failed! " + e.getMessage());
//            response.put("statusCode", 400);
//            response.put("data", null);
//            return response;
//        } catch (Exception e) {
//            response.put("message", "Internal Error during registration: " + e.getMessage());
//            response.put("statusCode", 500);
//            response.put("data", null);
//            return response;
//        }
//    }
//}
