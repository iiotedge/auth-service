package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class PasswordResetConfirmDTO {
    @NotBlank
    private String identifier; // same username or email passed to /password-reset/init

    @NotBlank
    private String otp;

    @NotBlank(message = "New password is required")
    // Same policy as registration/admin-created users.
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,50}$",
            message = "Password must be 8-50 characters with at least one uppercase, one lowercase, one number, and one special character")
    private String newPassword;
}
