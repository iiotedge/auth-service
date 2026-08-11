package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class MfaVerifyRequest {
    @NotBlank
    private String identifier; // the same identifier returned by the mfaRequired login response

    @NotBlank
    private String otp;
}
