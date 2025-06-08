package com.iotmining.services.auth.services;

import java.util.*;
import java.util.stream.Collectors;

import com.iotmining.services.auth.dto.*;
import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.exceptions.UserMessageException;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service

public class UserService {

    private final AuthenticationManager authenticationManager;
    private final UserLoginDataService userLoginDataService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;

    @Value("${tenant.service.url}")
    private String tenantServiceUrl;

    private final Map<String, Object> response = new HashMap<>();

    public UserService(AuthenticationManager authenticationManager, UserLoginDataService userLoginDataService, UserRepository userRepository, PasswordEncoder passwordEncoder, RestTemplate restTemplate) {
        this.authenticationManager = authenticationManager;
        this.userLoginDataService = userLoginDataService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> verify(UserCredentialDTO request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            if (authentication.isAuthenticated()) {
                AuthResponseDTO authResponseDTO = new AuthResponseDTO();

                UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

                if (!userPrincipal.isEnabled()) {
                    authResponseDTO.setAccessToken(null);
                    authResponseDTO.setIsAccountActive(false);
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

                authResponseDTO.setAccessToken(userLoginData.getConfirmationToken());
                authResponseDTO.setIsAccountActive(true);

                userLoginDataService.addUserAsyncLoginData(userLoginData);

                response.put("message", "Login successful");
                response.put("statusCode", 200);
                response.put("data", authResponseDTO);

                return response;
            }
            response.put("message", "Bad credentials");
            response.put("statusCode", 401);
            response.put("data", null);
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

    public Map<String, Object> registerUser(RegisterDTO request) {

        try {
            if (request.getRoles().contains("ROLE_SUPER_ADMIN")) {
                throw new UserMessageException("You are not authorized to create a Super Admin account, Thanks.");
            }

            User user = new User();
            user.setFirstName(request.getFirstName());
            user.setLastName(request.getLastName());
            user.setGender(request.getGender());
            user.setDateOfBirth(request.getDateOfBirth());
            user.setIsAccountActive(!request.getRoles().contains("ROLE_ADMIN"));
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setPhoneNumber(request.getPhoneNumber());
            user.setUsername(request.getUsername());
//            // ✅ Fetch existing Roles or create if not exists
//            Set<Role> userRoles = request.getRoles()
//                    .stream()
//                    .map(roleName -> roleRepository.findByRoleName(roleName)
//                            .orElseGet(() -> roleRepository.save(new Role(roleName))))
//                    .collect(Collectors.toSet());

//            user.setRoles(request.getRoles().stream().map(Role::new).collect(Collectors.toSet()));

            // Step 1: Save User first
//            User savedUser = userRepository.save(user);

            // Step 2: Call Tenant Management Service to create tenant
            CreateTenantRequest tenantRequest = new CreateTenantRequest(
                    user.getUsername(),
                    "BASIC" // default subscription plan
            );

            ResponseEntity<CreateTenantResponse> tenantResponse = restTemplate.postForEntity(
                    tenantServiceUrl,
                    tenantRequest,
                    CreateTenantResponse.class
            );

            if (tenantResponse.getStatusCode().is2xxSuccessful() && tenantResponse.getBody() != null) {
                UUID tenantId = tenantResponse.getBody().getTenantId();
                user.setTenantId(tenantId);
                userRepository.save(user); // Update with tenant ID
            } else {
                throw new RuntimeException("Failed to create tenant for user: " + user.getUsername());
            }

            response.put("message", "Register successful!");
            response.put("statusCode", 201);
            response.put("data", user);
            return response;

        } catch (DataIntegrityViolationException e) {
            response.put("message", "Username already exists.");
            response.put("statusCode", 409);
            response.put("data", null);
            return response;
        } catch (UserMessageException e) {
            response.put("message", "Register failed!, " + e.getMessage());
            response.put("statusCode", 400);
            response.put("data", null);
            return response;
        } catch (Exception e) {
            response.put("message", "Internal Error during registration: " + e.getMessage());
            response.put("statusCode", 500);
            response.put("data", null);
            return response;
        }
    }
}
