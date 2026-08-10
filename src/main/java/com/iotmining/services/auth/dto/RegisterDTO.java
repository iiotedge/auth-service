package com.iotmining.services.auth.dto;

import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.iotmining.services.auth.interfaces.ValidateGender;
import com.iotmining.services.auth.interfaces.ValidateMinimumAge;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true) // Prevents 500 errors if frontend sends extra fields
@JsonInclude(JsonInclude.Include.NON_NULL) // Keeps responses clean by hiding null values
public class RegisterDTO {

    @NotEmpty(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9._-]{3,50}$", message = "Username can only contain letters, numbers, dots, underscores, and hyphens")
    private String username;

    // --- NEW FIELD FOR OPTION B ---
    // This allows the user to explicitly name their Company/Tenant (e.g., "Acme IoT Solutions")
    @NotEmpty(message = "Organization Name is required")
    @Size(min = 2, max = 100, message = "Organization name must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-Z0-9\\s\\-'.&]+$", message = "Organization name contains invalid characters")
    private String organizationName;

    @NotEmpty(message = "First Name is required")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    // Updated regex to allow names like "O'Connor" or "Jean-Luc"
    @Pattern(regexp = "^[a-zA-Z\\s\\-']{2,50}$", message = "First name contains invalid characters")
    private String firstName;

    @NotEmpty(message = "Last Name is required")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z\\s\\-']{2,50}$", message = "Last name contains invalid characters")
    private String lastName;

    @NotEmpty(message = "Gender is required")
    @ValidateGender(message = "Gender must be either MALE, FEMALE, or OTHER") // Ensure your custom validator handles case-insensitivity
    private String gender;

    @NotEmpty(message = "Date of birth is required")
    @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}$", message = "Date of birth must be in the format yyyy-MM-dd")
    @ValidateMinimumAge(value = 18, message = "You must be at least 18 years old to register")
    private String dateOfBirth;

    // Optional: Defaults to USER or ADMIN in service logic if empty
    private List<String> roles;

    @NotEmpty(message = "Password is required")
    // Industry standard: Min 8 chars, 1 Upper, 1 Lower, 1 Digit, 1 Special Char
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,50}$",
            message = "Password must be 8-50 characters with at least one uppercase, one lowercase, one number, and one special character")
    private String password;

    @NotEmpty(message = "Email is required")
    @Email(regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Invalid email address format")
    private String email;

    @NotEmpty(message = "Phone number is required")
    // E.164 Standard Regex (Matches +919876543210 or 9876543210)
    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid phone number. Please use international format (e.g., +919876543210)")
    private String phoneNumber;

    // Optional: Used if inviting a user to an EXISTING tenant
    private UUID parentTenantId;

    // Optional: "SMS" or "EMAIL"
    @Pattern(regexp = "^(SMS|EMAIL|sms|email)$", message = "OTP Channel must be 'SMS' or 'EMAIL'")
    private String otpChannel;
}

