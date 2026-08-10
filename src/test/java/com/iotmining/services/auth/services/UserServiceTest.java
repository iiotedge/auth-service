package com.iotmining.services.auth.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotmining.common.base.notifications.dto.BaseResponse;
import com.iotmining.common.base.notifications.dto.NotificationResponse;
import com.iotmining.services.auth.clients.NotificationClient;
import com.iotmining.services.auth.dto.AuthResponseDTO;
import com.iotmining.services.auth.dto.CreateTenantResponse;
import com.iotmining.services.auth.dto.OtpResendRequest;
import com.iotmining.services.auth.dto.OtpVerifyRequest;
import com.iotmining.services.auth.dto.RegisterDTO;
import com.iotmining.services.auth.dto.UserCreateDTO;
import com.iotmining.services.auth.dto.UserCredentialDTO;
import com.iotmining.services.auth.dto.UserLoginDataDTO;
import com.iotmining.services.auth.dto.UserSummaryDTO;
import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.repository.RoleRepository;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.support.TestDataFactory;
import com.iotmining.services.auth.util.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserService")
class UserServiceTest {

    private static final String TENANT_SERVICE_URL = "http://tms/api/v1/tenants";

    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserLoginDataService userLoginDataService;
    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private RestTemplate restTemplate;
    @Mock private NotificationClient notificationClient;
    @Mock private StringRedisTemplate redis;
    @Mock private ValueOperations<String, String> valueOps;

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private OtpStore otpStore;

    private UserService userService;

    @BeforeEach
    void setUp() {
        TestDataFactory.initJwtProvider();
        userService = new UserService(authenticationManager, userLoginDataService, userRepository,
                roleRepository, passwordEncoder, restTemplate, notificationClient, redis, objectMapper, otpStore);
        ReflectionTestUtils.setField(userService, "tenantServiceUrl", TENANT_SERVICE_URL);
        ReflectionTestUtils.setField(userService, "notificationBaseUrl", "http://notification:8087");
        ReflectionTestUtils.setField(userService, "maxFailedLoginAttempts", 5);
        ReflectionTestUtils.setField(userService, "lockoutDurationMinutes", 15L);
        ReflectionTestUtils.setField(userService, "maxOtpAttempts", 5);
        ReflectionTestUtils.setField(userService, "maxOtpResendsPerHour", 3);
    }

    // ==============================================================================
    // LOGIN
    // ==============================================================================
    @Nested
    @DisplayName("verify (login)")
    class Verify {

        @Test
        @DisplayName("returns 200 with an access token for valid credentials")
        void loginSuccess() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            stubAuthenticatedPrincipal(user);

            Map<String, Object> response = userService.verify(new UserCredentialDTO("john.doe", "Str0ng@Pass"));

            assertThat(response.get("statusCode")).isEqualTo(200);
            assertThat(response.get("message")).isEqualTo("Login successful");
            AuthResponseDTO auth = (AuthResponseDTO) response.get("data");
            assertThat(auth.getAccessToken()).isNotBlank();
            assertThat(auth.getIsAccountActive()).isTrue();
            assertThat(JwtTokenProvider.extractUserName(auth.getAccessToken())).isEqualTo("john.doe");
        }

        @Test
        @DisplayName("records the login event asynchronously on success")
        void loginRecordsLoginEvent() {
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            stubAuthenticatedPrincipal(user);

            userService.verify(new UserCredentialDTO("john.doe", "Str0ng@Pass"));

            ArgumentCaptor<UserLoginDataDTO> captor = ArgumentCaptor.forClass(UserLoginDataDTO.class);
            verify(userLoginDataService).addUserAsyncLoginData(captor.capture());
            assertThat(captor.getValue().getUser()).isSameAs(user);
            assertThat(captor.getValue().getAccessToken()).isNotBlank();
        }

        @Test
        @DisplayName("returns 401 without leaking detail on bad credentials")
        void loginBadCredentials() {
            when(authenticationManager.authenticate(any()))
                    .thenThrow(new BadCredentialsException("bad"));

            Map<String, Object> response = userService.verify(new UserCredentialDTO("john.doe", "wrong"));

            assertThat(response.get("statusCode")).isEqualTo(401);
            assertThat(response.get("message")).isEqualTo("Invalid username or password");
            assertThat(response).doesNotContainKey("data");
            verify(userLoginDataService, never()).addUserAsyncLoginData(any());
        }

        @Test
        @DisplayName("rejects a disabled account (currently surfaced as 500)")
        void loginDisabledAccount() {
            // Documents current behavior: the disabled-account UserMessageException is
            // swallowed by the generic catch block and mapped to 500 instead of 401/403.
            User user = TestDataFactory.user("john.doe", "ROLE_USER");
            user.setIsAccountActive(false);
            stubAuthenticatedPrincipal(user);

            Map<String, Object> response = userService.verify(new UserCredentialDTO("john.doe", "Str0ng@Pass"));

            assertThat(response.get("statusCode")).isEqualTo(500);
            assertThat(response).doesNotContainKey("data");
            verify(userLoginDataService, never()).addUserAsyncLoginData(any());
        }

        @Test
        @DisplayName("returns 500 on unexpected authentication failure")
        void loginUnexpectedError() {
            when(authenticationManager.authenticate(any()))
                    .thenThrow(new IllegalStateException("auth backend down"));

            Map<String, Object> response = userService.verify(new UserCredentialDTO("john.doe", "Str0ng@Pass"));

            assertThat(response.get("statusCode")).isEqualTo(500);
            assertThat(response.get("message")).isEqualTo("Internal Server Error");
        }

        private void stubAuthenticatedPrincipal(User user) {
            Authentication authentication = mock(Authentication.class);
            when(authentication.getPrincipal()).thenReturn(new UserPrincipal(user));
            when(authenticationManager.authenticate(any())).thenReturn(authentication);
        }
    }

    // ==============================================================================
    // REGISTRATION PHASE 1
    // ==============================================================================
    @Nested
    @DisplayName("registerInit")
    class RegisterInit {

        @Test
        @DisplayName("rejects public self-registration as SUPER_ADMIN")
        void rejectsSuperAdminRegistration() {
            RegisterDTO request = TestDataFactory.validRegistration();
            request.setRoles(List.of("ROLE_SUPER_ADMIN"));

            Map<String, Object> response = userService.registerInit(request);

            assertThat(response.get("statusCode")).isEqualTo(400);
            assertThat((String) response.get("message")).contains("Authorization Error");
            verify(otpStore, never()).saveNew(anyString(), anyString(), anyMap(), any());
        }

        @Test
        @DisplayName("returns 409 when the username is already taken")
        void rejectsDuplicateUsername() {
            RegisterDTO request = TestDataFactory.validRegistration();
            when(userRepository.existsByUsername(request.getUsername())).thenReturn(true);

            Map<String, Object> response = userService.registerInit(request);

            assertThat(response.get("statusCode")).isEqualTo(409);
            verify(otpStore, never()).saveNew(anyString(), anyString(), anyMap(), any());
        }

        @Test
        @DisplayName("stores pending registration and returns 202 once the OTP is delivered")
        void sendsOtpAndReturnsAccepted() {
            RegisterDTO request = TestDataFactory.validRegistration();
            when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
            when(otpStore.generateCode()).thenReturn("123456");
            when(redis.opsForValue()).thenReturn(valueOps);
            stubNotificationDelivery(true);

            Map<String, Object> response = userService.registerInit(request);

            assertThat(response.get("statusCode")).isEqualTo(202);
            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) response.get("data");
            assertThat((String) data.get("prospectId")).isNotBlank();
            assertThat(data.get("otpChannel")).isEqualTo("EMAIL");
            verify(otpStore).saveNew(anyString(), eq("123456"), anyMap(), any());
            verify(valueOps).set(contains("reg:prospect:"), anyString(), any());
            verify(valueOps).set(contains("reg:index:EMAIL:"), anyString(), any());
        }

        @Test
        @DisplayName("prefers SMS when requested and a phone number exists")
        void honorsSmsChannel() {
            RegisterDTO request = TestDataFactory.validRegistration();
            request.setOtpChannel("SMS");
            when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
            when(otpStore.generateCode()).thenReturn("123456");
            when(redis.opsForValue()).thenReturn(valueOps);
            stubNotificationDelivery(true);

            Map<String, Object> response = userService.registerInit(request);

            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) response.get("data");
            assertThat(data.get("otpChannel")).isEqualTo("SMS");
        }

        @Test
        @DisplayName("cleans up pending state and returns 500 when OTP delivery fails everywhere")
        void cleansUpWhenDeliveryFails() {
            RegisterDTO request = TestDataFactory.validRegistration();
            when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
            when(otpStore.generateCode()).thenReturn("123456");
            when(redis.opsForValue()).thenReturn(valueOps);
            stubNotificationDelivery(false);

            Map<String, Object> response = userService.registerInit(request);

            assertThat(response.get("statusCode")).isEqualTo(500);
            assertThat((String) response.get("message")).contains("Registration failed");
            verify(redis).delete(contains("reg:prospect:"));
        }
    }

    // ==============================================================================
    // REGISTRATION PHASE 2 (OTP VERIFY)
    // ==============================================================================
    @Nested
    @DisplayName("verifyOtp")
    class VerifyOtp {

        private final RegisterDTO registration = TestDataFactory.validRegistration();
        private final String prospectId = UUID.randomUUID().toString();
        private final String indexKey = "reg:index:EMAIL:john.doe@example.com";
        private final String regKey = "reg:prospect:" + prospectId;

        @Test
        @DisplayName("returns 400 when identifier or type is missing")
        void rejectsMissingFields() {
            OtpVerifyRequest request = new OtpVerifyRequest();
            request.setOtp("123456");

            Map<String, Object> response = userService.verifyOtp(request);

            assertThat(response.get("statusCode")).isEqualTo(400);
        }

        @Test
        @DisplayName("returns 404 when no pending registration exists")
        void rejectsUnknownSession() {
            when(redis.opsForValue()).thenReturn(valueOps);
            when(valueOps.get(indexKey)).thenReturn(null);

            Map<String, Object> response = userService.verifyOtp(verifyRequest("123456"));

            assertThat(response.get("statusCode")).isEqualTo(404);
        }

        @Test
        @DisplayName("returns 400 for a wrong OTP")
        void rejectsInvalidOtp() {
            when(redis.opsForValue()).thenReturn(valueOps);
            when(valueOps.get(indexKey)).thenReturn(prospectId);
            when(otpStore.verify(prospectId, "000000")).thenReturn(false);

            Map<String, Object> response = userService.verifyOtp(verifyRequest("000000"));

            assertThat(response.get("statusCode")).isEqualTo(400);
            assertThat(response.get("message")).isEqualTo("Invalid OTP");
        }

        @Test
        @DisplayName("creates tenant and user, cleans up Redis, and returns 201")
        void createsUserOnValidOtp() throws Exception {
            stubValidOtpSession();
            UUID tenantId = UUID.randomUUID();
            stubTenantCreation(tenantId);
            when(passwordEncoder.encode(registration.getPassword())).thenReturn("ENCODED_PASSWORD");
            when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(new Role("ROLE_USER")));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User saved = invocation.getArgument(0);
                saved.setUserId(UUID.randomUUID());
                return saved;
            });

            Map<String, Object> response = userService.verifyOtp(verifyRequest("123456"));

            assertThat(response.get("statusCode")).isEqualTo(201);
            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) response.get("data");
            assertThat(data.get("tenantId")).isEqualTo(tenantId);
            assertThat(data.get("userId")).isNotNull();
            assertThat(data.get("organizationName")).isEqualTo(registration.getOrganizationName());

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            User saved = userCaptor.getValue();
            assertThat(saved.getPassword()).isEqualTo("ENCODED_PASSWORD");
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getIsAccountActive()).isTrue();

            verify(otpStore).delete(prospectId);
            verify(redis).delete(regKey);
        }

        @Test
        @DisplayName("returns 503 when the tenant service is unavailable")
        void failsWhenTenantServiceDown() throws Exception {
            stubValidOtpSession();
            when(restTemplate.postForEntity(eq(TENANT_SERVICE_URL), any(HttpEntity.class),
                    eq(CreateTenantResponse.class))).thenThrow(new RestClientException("connection refused"));

            Map<String, Object> response = userService.verifyOtp(verifyRequest("123456"));

            assertThat(response.get("statusCode")).isEqualTo(503);
            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("compensates by deleting the tenant when the user save fails")
        void rollsBackTenantWhenUserSaveFails() throws Exception {
            stubValidOtpSession();
            UUID tenantId = UUID.randomUUID();
            stubTenantCreation(tenantId);
            when(passwordEncoder.encode(anyString())).thenReturn("ENCODED_PASSWORD");
            when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(new Role("ROLE_USER")));
            when(userRepository.save(any(User.class))).thenThrow(new RuntimeException("constraint violation"));

            Map<String, Object> response = userService.verifyOtp(verifyRequest("123456"));

            assertThat(response.get("statusCode")).isEqualTo(500);
            assertThat((String) response.get("message")).contains("rolled back");
            verify(restTemplate).exchange(eq(TENANT_SERVICE_URL + "/internal/" + tenantId),
                    eq(HttpMethod.DELETE), any(HttpEntity.class), eq(Void.class));
        }

        private OtpVerifyRequest verifyRequest(String otp) {
            OtpVerifyRequest request = new OtpVerifyRequest();
            request.setIdentifier("john.doe@example.com");
            request.setOtp(otp);
            request.setType("EMAIL");
            return request;
        }

        private void stubValidOtpSession() throws Exception {
            when(redis.opsForValue()).thenReturn(valueOps);
            when(valueOps.get(indexKey)).thenReturn(prospectId);
            when(otpStore.verify(prospectId, "123456")).thenReturn(true);
            when(valueOps.get(regKey)).thenReturn(objectMapper.writeValueAsString(registration));
        }

        private void stubTenantCreation(UUID tenantId) {
            CreateTenantResponse tenantResponse = new CreateTenantResponse();
            tenantResponse.setTenantId(tenantId);
            when(restTemplate.postForEntity(eq(TENANT_SERVICE_URL), any(HttpEntity.class),
                    eq(CreateTenantResponse.class))).thenReturn(ResponseEntity.ok(tenantResponse));
        }
    }

    // ==============================================================================
    // RESEND OTP
    // ==============================================================================
    @Nested
    @DisplayName("resendOtp")
    class ResendOtp {

        private final String indexKey = "reg:index:EMAIL:john.doe@example.com";
        private final String prospectId = UUID.randomUUID().toString();
        private final String regKey = "reg:prospect:" + prospectId;

        @Test
        @DisplayName("returns 400 when the identifier is missing")
        void rejectsMissingIdentifier() {
            Map<String, Object> response = userService.resendOtp(new OtpResendRequest());

            assertThat(response.get("statusCode")).isEqualTo(400);
        }

        @Test
        @DisplayName("returns 404 when there is no pending registration")
        void rejectsUnknownRegistration() {
            when(redis.opsForValue()).thenReturn(valueOps);
            when(valueOps.get(indexKey)).thenReturn(null);

            Map<String, Object> response = userService.resendOtp(resendRequest());

            assertThat(response.get("statusCode")).isEqualTo(404);
        }

        @Test
        @DisplayName("returns 429 when the resend budget is exhausted")
        void enforcesResendBudget() throws Exception {
            stubPendingRegistration();
            doThrow(new RuntimeException("Resend limit reached"))
                    .when(otpStore).ensureResendBudget(prospectId, 5);

            Map<String, Object> response = userService.resendOtp(resendRequest());

            assertThat(response.get("statusCode")).isEqualTo(429);
            verify(otpStore, never()).replaceOtp(anyString(), anyString(), anyMap(), any());
        }

        @Test
        @DisplayName("issues a fresh OTP and returns 202")
        void resendsOtp() throws Exception {
            stubPendingRegistration();
            when(otpStore.generateCode()).thenReturn("654321");
            stubNotificationDelivery(true);

            Map<String, Object> response = userService.resendOtp(resendRequest());

            assertThat(response.get("statusCode")).isEqualTo(202);
            verify(otpStore).replaceOtp(eq(prospectId), eq("654321"), anyMap(), any());
            verify(valueOps).set(eq(regKey), anyString(), any());
        }

        private OtpResendRequest resendRequest() {
            OtpResendRequest request = new OtpResendRequest();
            request.setIdentifier("john.doe@example.com");
            return request;
        }

        private void stubPendingRegistration() throws Exception {
            when(redis.opsForValue()).thenReturn(valueOps);
            when(valueOps.get(indexKey)).thenReturn(prospectId);
            when(valueOps.get(regKey))
                    .thenReturn(objectMapper.writeValueAsString(TestDataFactory.validRegistration()));
        }
    }

    // ==============================================================================
    // INTERNAL USER CREATION
    // ==============================================================================
    @Nested
    @DisplayName("createUserInternal")
    class CreateUserInternal {

        @Test
        @DisplayName("forces the new user into the admin's tenant and encodes the password")
        void createsUserInAdminTenant() {
            UUID adminTenantId = UUID.randomUUID();
            UserCreateDTO request = userCreateRequest();
            when(userRepository.existsByUsername("employee1")).thenReturn(false);
            when(userRepository.existsByEmail("employee1@acme.com")).thenReturn(false);
            when(passwordEncoder.encode("Empl0yee@1")).thenReturn("ENCODED_PASSWORD");
            when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(new Role("ROLE_USER")));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User saved = invocation.getArgument(0);
                saved.setUserId(UUID.randomUUID());
                return saved;
            });

            Map<String, Object> response = userService.createUserInternal(request, adminTenantId);

            assertThat(response.get("statusCode")).isEqualTo(201);
            assertThat(response.get("userId")).isNotNull();

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            User saved = captor.getValue();
            assertThat(saved.getTenantId()).isEqualTo(adminTenantId);
            assertThat(saved.getPassword()).isEqualTo("ENCODED_PASSWORD");
            assertThat(saved.getRoles()).extracting(Role::getName).containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("rejects a duplicate username (currently surfaced as 500)")
        void rejectsDuplicateUsername() {
            // Documents current behavior: UserMessageException is caught by the generic
            // handler inside the service and mapped to 500 rather than 409.
            when(userRepository.existsByUsername("employee1")).thenReturn(true);

            Map<String, Object> response = userService.createUserInternal(userCreateRequest(), UUID.randomUUID());

            assertThat(response.get("statusCode")).isEqualTo(500);
            assertThat((String) response.get("message")).contains("Username taken");
            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("rejects a duplicate email (currently surfaced as 500)")
        void rejectsDuplicateEmail() {
            when(userRepository.existsByUsername("employee1")).thenReturn(false);
            when(userRepository.existsByEmail("employee1@acme.com")).thenReturn(true);

            Map<String, Object> response = userService.createUserInternal(userCreateRequest(), UUID.randomUUID());

            assertThat(response.get("statusCode")).isEqualTo(500);
            assertThat((String) response.get("message")).contains("Email taken");
            verify(userRepository, never()).save(any(User.class));
        }

        private UserCreateDTO userCreateRequest() {
            UserCreateDTO request = new UserCreateDTO();
            request.setUsername("employee1");
            request.setEmail("employee1@acme.com");
            request.setFirstName("Emma");
            request.setLastName("Ployee");
            request.setPassword("Empl0yee@1");
            return request;
        }
    }

    // ==============================================================================
    // TENANT USER LISTING
    // ==============================================================================
    @Nested
    @DisplayName("findUsersByTenantId")
    class FindUsersByTenantId {

        @Test
        @DisplayName("maps users to summaries, defaulting access level when roles are missing")
        void mapsUsersToSummaries() {
            UUID tenantId = UUID.randomUUID();
            User admin = TestDataFactory.user("admin.user", "ROLE_ADMIN");
            User bare = TestDataFactory.user("bare.user");
            bare.setRoles(null); // must not blow up on missing roles
            when(userRepository.findByTenantId(tenantId)).thenReturn(List.of(admin, bare));

            List<UserSummaryDTO> summaries = userService.findUsersByTenantId(tenantId);

            assertThat(summaries).hasSize(2);
            assertThat(summaries.get(0).getUsername()).isEqualTo("admin.user");
            assertThat(summaries.get(0).getAccessLevel()).isEqualTo("ROLE_ADMIN");
            assertThat(summaries.get(1).getAccessLevel()).isEqualTo("USER");
            assertThat(summaries.get(1).getEmail()).isEqualTo("bare.user@iotmining.com");
        }

        @Test
        @DisplayName("returns an empty list for a tenant without users")
        void returnsEmptyListForUnknownTenant() {
            UUID tenantId = UUID.randomUUID();
            when(userRepository.findByTenantId(tenantId)).thenReturn(List.of());

            assertThat(userService.findUsersByTenantId(tenantId)).isEmpty();
        }
    }

    // ==============================================================================
    // SHARED STUBS
    // ==============================================================================
    private void stubNotificationDelivery(boolean delivered) {
        if (delivered) {
            BaseResponse<NotificationResponse> ok = new BaseResponse<>();
            ok.setSuccess(true);
            when(notificationClient.sendInternalPreReg(anyString(), anyString(), anyMap()))
                    .thenReturn(ResponseEntity.ok(ok));
        } else {
            when(notificationClient.sendInternalPreReg(anyString(), anyString(), anyMap()))
                    .thenThrow(new RuntimeException("feign down"));
            when(restTemplate.postForEntity(anyString(), any(), eq(String.class)))
                    .thenThrow(new RestClientException("notification service down"));
        }
    }
}
