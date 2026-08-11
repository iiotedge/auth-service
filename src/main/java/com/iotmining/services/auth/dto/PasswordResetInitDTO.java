package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordResetInitDTO {
    @NotBlank
    private String identifier; // username or email
}
