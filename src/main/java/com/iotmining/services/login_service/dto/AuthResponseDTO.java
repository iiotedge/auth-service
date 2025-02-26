package com.iotmining.services.login_service.dto;

import lombok.Data;

@Data
public class AuthResponseDTO {
    private String accessToken;
    private Boolean isAccountActive;
}
