package com.iotmining.services.login_service.services;

import java.util.List;
import java.util.stream.Collectors;

import com.iotmining.services.login_service.dto.GenericResponseDTO;
import com.iotmining.services.login_service.dto.RegisterDTO;
import com.iotmining.services.login_service.dto.UserCredentialDTO;
import com.iotmining.services.login_service.dto.UserLoginDataDTO;
import com.iotmining.services.login_service.exceptions.UserMessageException;
import com.iotmining.services.login_service.repository.UserRepository;
import com.iotmining.services.login_service.security.UserPrincipal;
import com.iotmining.services.login_service.util.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.iotmining.services.login_service.dto.AuthResponseDTO;
import com.iotmining.services.login_service.entity.User;

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

    public GenericResponseDTO<?> verify(UserCredentialDTO request) {
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

                return new GenericResponseDTO<>("Login successful", 200, authResponseDTO);
            }
            return new GenericResponseDTO<>("Bad credentials", 401, null);

        } catch (UserMessageException e) {
            return new GenericResponseDTO<>(e.getMessage(), 401, null);
        } catch (RuntimeException e) {
            return new GenericResponseDTO<>(e.getMessage(), 401, null);
          //  return new GenericResponseDTO<>("error occur, please contact support team.", 401, null);
        }
    }

    public GenericResponseDTO<?> registerUser(RegisterDTO request) {

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

            return new GenericResponseDTO<>("Register successful!", 201, userResponse);

        } catch (UserMessageException e) {
            return new GenericResponseDTO<>("Register failed!, " + e.getMessage(), 400, null);
        }

    }
}
