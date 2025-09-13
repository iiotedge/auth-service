package com.iotmining.services.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateTenantRequest {
    private String tenantName;
    private String subscriptionPlan;
    private UUID parentId;
    private List<String> roles; // Pass roles here for mapping
}
