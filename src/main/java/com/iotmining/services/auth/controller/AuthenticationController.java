package com.iotmining.services.auth.controller;

import com.iotmining.services.auth.util.JwtTokenProvider;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.iotmining.services.auth.services.UserService;
import com.iotmining.services.auth.dto.RegisterDTO;
import com.iotmining.services.auth.dto.UserCredentialDTO;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;

import java.util.Map;

@RestController
@RequestMapping(value = "/api/v1/auth")
@Log4j2
public class AuthenticationController {

    @Autowired
    private UserService userService;

    private Map<String, Object> response;

    /**
     * Logs in a user with the given username and password.
     *
     * @param loginRequest The username and password of the user
     * @return JWT token as a string if authentication is successful
     */
    @PostMapping("/login")
    @Operation(summary = "Login, with credentials", description = "Returns a login token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(mediaType = "application/json"))
    })
    public ResponseEntity<Map<String, Object>> login(@RequestBody @Valid UserCredentialDTO loginRequest) {

        log.info("Login attempt for user: {}", loginRequest.getUsername());

        response = userService.verify(loginRequest);
        if ((Integer) response.get("statusCode") == 200) {
            log.info("Login successful for user: {}", loginRequest.getUsername());
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        else if ((Integer) response.get("statusCode") == 500) {
            log.warn("[Server Error] Failed login attempt for user: {}", loginRequest.getUsername());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        } else {
            log.warn("Failed login attempt for user: {}", loginRequest.getUsername());
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Validates an authentication token.
     *
     * @param token The JWT token to be validated
     * @return HTTP 200 if valid, otherwise HTTP 401
     */
    @GetMapping("/validate")
    @Operation(summary = "Validate Token", description = "Validates the JWT authentication token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token is valid"),
            @ApiResponse(responseCode = "401", description = "Invalid or expired token")
    })
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String token) {
        log.info("Token validation request received");
        if (JwtTokenProvider.validateToken(token.replace("Bearer ", ""))) {
            log.info("Token is valid");
            return ResponseEntity.ok().build();
        } else {
            log.warn("Token validation failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    /**
     * Logs out a user by invalidating their token.
     *
     * @param token The JWT token to be invalidated
     * @return HTTP 200 if logout is successful
     */
    @PostMapping("/logout")
    @Operation(summary = "User Logout", description = "Invalidates the authentication token and logs out the user.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Logout successful"),
            @ApiResponse(responseCode = "400", description = "Token not provided")
    })
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
        if (token != null) {
            log.info("Logout request received with token");
            // logoutService.blacklistToken(token);
        } else {
            log.warn("Logout request received without token");
            return ResponseEntity.badRequest().body("Token not provided");
        }
        log.info("Logout successful");
        return ResponseEntity.ok("Logout successful!");
    }

    /**
     * Registers a new user.
     *
     * @param register The registration details
     * @return HTTP 201 if registration is successful, otherwise appropriate HTTP status
     */
    @PostMapping("/register")
    @Operation(summary = "User Registration", description = "Registers a new user with a unique username and password.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User registered successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "409", description = "Username already exists"),
            @ApiResponse(responseCode = "400", description = "Invalid request data")
    })
    public ResponseEntity<Map<String, Object>> register(@RequestBody @Valid RegisterDTO register) {
        log.info("Registration request for user: {}", register.getUsername());
        response = userService.registerUser(register);
        if ((Integer) response.get("statusCode") == 201) {
            log.info("User registered successfully: {}", register.getUsername());
            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } else if ((Integer) response.get("statusCode") == 409) {
            log.warn("Username already exists, Failed register attempt for user: {}", register.getUsername());
            return new ResponseEntity<>(response, HttpStatus.CONFLICT);
        } else {
            log.warn("User registration failed: {}", register.getUsername());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }
}
