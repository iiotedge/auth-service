package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import java.util.List;

@Data
public class UserCreateDTO {
    @NotEmpty(message = "Username is required")
    private String username;

    @NotEmpty(message = "Email is required")
    @Email
    private String email;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    // Same policy as self-registration (RegisterDTO) - an admin-created
    // account shouldn't be allowed a weaker password than a self-registered one.
    @NotEmpty
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,50}$",
            message = "Password must be 8-50 characters with at least one uppercase, one lowercase, one number, and one special character")
    private String password;

    private List<String> roles; // e.g. ["ROLE_USER", "ROLE_MANAGER"]
}