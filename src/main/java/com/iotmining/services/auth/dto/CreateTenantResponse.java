package com.iotmining.services.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateTenantResponse {
    private UUID tenantId;
    private String tenantName;
    private String subscriptionPlan;
    private String keyspaceName;
    private Instant createdAt;
}
