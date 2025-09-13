// src/main/java/com/iotmining/services/auth/dto/NotificationRequest.java
package com.iotmining.services.auth.dto;

import lombok.*;

import java.util.Map;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class NotificationRequest {
    private String type;          // "SMS", "EMAIL", "WEB", "TELEGRAM"
    private String userId;        // can be null for pre-tenant
    private String correlationId; // optional
    private String sourceApp;     // e.g. "auth-service"
    private String priority;      // "LOW" | "MEDIUM" | "HIGH"
    private int retryCount;
    private long timestamp;       // System.currentTimeMillis()
    private Map<String, Object> payload;
}
