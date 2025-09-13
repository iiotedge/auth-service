package com.iotmining.services.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class OtpVerifyRequest {
    @NotBlank
    private String identifier; // phone or email used during /register (or after channel switch)

    @NotBlank
    private String otp;

    // Must match the channel used to send the OTP
    @NotBlank
    @Pattern(regexp = "SMS|EMAIL|TELEGRAM", message = "type must be either SMS or EMAIL")
    private String type;
}
