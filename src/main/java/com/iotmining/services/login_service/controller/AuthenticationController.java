package com.iotmining.services.login_service.controller;

import com.iotmining.services.login_service.util.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.iotmining.services.login_service.services.UserService;
import com.iotmining.services.login_service.dto.GenericResponseDTO;
import com.iotmining.services.login_service.dto.RegisterDTO;
import com.iotmining.services.login_service.dto.UserCredentialDTO;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;

@RestController
@RequestMapping(value = "/api/v1/auth")
public class AuthenticationController {

    private static final Logger logger = LogManager.getLogger(AuthenticationController.class);

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    @Operation(summary = "Login, with credentials", description = "Returns a login token")
    public ResponseEntity<?> login(@RequestBody @Valid UserCredentialDTO loginRequest) {
        logger.info("Login attempt for user: {}", loginRequest.getUsername());
        GenericResponseDTO<?> response = userService.verify(loginRequest);
        if (response.getStatusCode() == 200) {
            logger.info("Login successful for user: {}", loginRequest.getUsername());
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            logger.warn("Failed login attempt for user: {}", loginRequest.getUsername());
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String token) {
        logger.info("Token validation request received");
        if (JwtTokenProvider.validateToken(token.replace("Bearer ", ""))) {
            logger.info("Token is valid");
            return ResponseEntity.ok().build();
        } else {
            logger.warn("Token validation failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
        if (token != null) {
            logger.info("Logout request received with token");
            // logoutService.blacklistToken(token);
        } else {
            logger.warn("Logout request received without token");
            return ResponseEntity.badRequest().body("Token not provided");
        }
        logger.info("Logout successful");
        return ResponseEntity.ok("Logout successful!");
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterDTO register) {
        logger.info("Registration request for user: {}", register.getUsername());

        GenericResponseDTO<?> response = userService.registerUser(register);
        if (response.getStatusCode() == 201) {
            logger.info("User registered successfully: {}", register.getUsername());
            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } else {
            logger.warn("User registration failed: {}", register.getUsername());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }
}
