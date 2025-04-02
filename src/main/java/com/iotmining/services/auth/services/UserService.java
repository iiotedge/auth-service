package com.iotmining.services.auth.services;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.iotmining.services.auth.dto.RegisterDTO;
import com.iotmining.services.auth.dto.UserCredentialDTO;
import com.iotmining.services.auth.dto.UserLoginDataDTO;
import com.iotmining.services.auth.exceptions.UserMessageException;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.util.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.iotmining.services.auth.dto.AuthResponseDTO;
import com.iotmining.services.auth.entity.User;

@Service
public class UserService {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserLoginDataService userLoginDataService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    Map<String, Object> response = new HashMap<>();
    /**
     * Logs in a user with the given username and password.
     *
     * @param request The username and password of the user
     * @return JWT token as a string if authentication is successful
     * @throws BadCredentialsException Throw if username and password invalid
     * @throws RuntimeException Occur when system issue
     * @throws UserMessageException Throw custom exception for user e.g.- "when account is not active"
     */
    public Map<String, Object> verify(UserCredentialDTO request) {
        try {

            Authentication authentication = authenticationManager
                    .authenticate(
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
                userLoginData.setUserId(user.getUserId());
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
            response.put("message", "Internal Server Error" + e.getMessage());
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

            User userResponse = userRepository.save(user);
            response.put("message", "Register successful!");
            response.put("statusCode", 201);
            response.put("data", userResponse);
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
        }
    }
}
