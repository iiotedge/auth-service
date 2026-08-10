package com.iotmining.services.auth.dto;

import lombok.Data;
import java.util.UUID;

@Data
public class UserSummaryDTO {
    private UUID userId;
    private String username;
    private String email;
    private String accessLevel;
}
