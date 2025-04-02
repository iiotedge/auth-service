package com.iotmining.services.auth.dto;

import java.util.List;

import com.iotmining.services.auth.interfaces.ValidateGender;
import com.iotmining.services.auth.interfaces.ValidateMinimumAge;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterDTO {

    @NotEmpty(message = "Username is mandatory field")
    @Size(min = 3, max = 25, message = "Username must be between 3 and 20 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]{3,25}$", message = "Invalid username format")
    private String username;

    @Pattern(regexp = "^[a-zA-Z\\s]{3,25}$", message = "Invalid name format")
    private String firstName;

    private String lastName;

    @NotEmpty(message = "Gender is mandatory field")
    @ValidateGender(message = "Gender must be either male or female")
    private String gender;

    @NotEmpty(message = "Date of birth is mandatory field")
    @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}$", message = "Date of birth must be in the format yyyy-MM-dd")
    @ValidateMinimumAge(value = 18, message = "Age must be greater than 18 years")
    private String dateOfBirth;

    private List<String> roles;

    @NotEmpty(message = "Password is mandatory")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{6,20}$", message = "Password must be in between 6-20 characters and contain at least one lowercase letter, one uppercase letter, one digit, and one special character")
    private String password;

    @NotEmpty(message = "Email is mandatory field")
    @Email(message = "Invalid email address")
    private String email;

    @NotEmpty(message = "Phone No. is mandatory field")
    @Pattern(regexp = "^[6789]\\d{9}$", message = "Invalid phone number")
    private String phoneNumber;

}
