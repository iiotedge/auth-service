package com.iotmining.services.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenRefreshResponse {
    private String accessToken;
    private String tokenType = "Bearer";

    public TokenRefreshResponse(String accessToken) {
        this.accessToken = accessToken;
    }
}