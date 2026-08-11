package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DisableMfaRequest {
    // Re-proves identity before turning off a security control, so a
    // hijacked-but-not-yet-expired session token alone can't disable MFA.
    @NotBlank
    private String currentPassword;
}
