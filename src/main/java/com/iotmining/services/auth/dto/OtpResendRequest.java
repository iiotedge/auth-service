package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class OtpResendRequest {
    @NotBlank
    private String identifier; // the CURRENT identifier that holds the OTP (phone or email)

    // Optional: if provided and different than stored channel,
    // we will switch only when allowSwitch=true and the other identifier exists.
    @Pattern(regexp = "SMS|EMAIL|TELEGRAM", message = "type must be either SMS or EMAIL")
    private String OtpChannel; // nullable

    // Explicitly allow switching channel (and identifier) on resend
    private boolean allowSwitch = false;
}
