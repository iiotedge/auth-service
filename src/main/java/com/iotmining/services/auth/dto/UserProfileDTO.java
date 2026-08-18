package com.iotmining.services.auth.dto;

import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class UserProfileDTO {
    private UUID userId;
    private UUID tenantId;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private List<String> roles;
    private boolean mfaEnabled;
}
