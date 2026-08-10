package com.iotmining.services.auth.exceptions;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("GlobalExceptionHandler")
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    @DisplayName("maps bean-validation failures to a 400 with field → message entries")
    void mapsValidationErrors() throws NoSuchMethodException {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "loginRequest");
        bindingResult.addError(new FieldError("loginRequest", "username", "Username is mandatory"));
        bindingResult.addError(new FieldError("loginRequest", "password", "Password is mandatory"));
        MethodParameter parameter = new MethodParameter(
                getClass().getDeclaredMethod("sampleMethod", String.class), 0);
        MethodArgumentNotValidException exception = new MethodArgumentNotValidException(parameter, bindingResult);

        ResponseEntity<Map<String, Object>> response = handler.handleValidationExceptions(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody())
                .containsEntry("statusCode", 400)
                .containsEntry("error", "Validation Failed")
                .containsEntry("username", "Username is mandatory")
                .containsEntry("password", "Password is mandatory");
    }

    @Test
    @DisplayName("maps UserMessageException to a 400 with the user-facing message")
    void mapsUserMessageException() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleUserMessageException(new UserMessageException("Account is disabled"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody())
                .containsEntry("statusCode", 400)
                .containsEntry("message", "Account is disabled");
    }

    @Test
    @DisplayName("maps RateLimitExceededException to a 429")
    void mapsRateLimitException() {
        ResponseEntity<String> response =
                handler.handleRateLimitExceededException(new RateLimitExceededException("Too many requests"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getBody()).isEqualTo("Too many requests");
    }

    @Test
    @DisplayName("maps AccessDeniedException to a 403")
    void mapsAccessDeniedException() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleAccessDeniedException(new AccessDeniedException("Not authorized to view users for this tenant."));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody())
                .containsEntry("statusCode", 403)
                .containsEntry("error", "Forbidden")
                .containsEntry("message", "Not authorized to view users for this tenant.");
    }

    @Test
    @DisplayName("maps unexpected exceptions to a 500 without leaking internals")
    void mapsUnexpectedException() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleUnexpectedException(new IllegalStateException("db connection pool exhausted"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody())
                .containsEntry("statusCode", 500)
                .containsEntry("error", "Internal Server Error")
                .extractingByKey("message")
                .asString()
                .doesNotContain("db connection pool exhausted");
    }

    @SuppressWarnings("unused")
    private void sampleMethod(String argument) {
        // referenced reflectively to build a MethodParameter for the validation test
    }
}
