package com.iotmining.services.auth.clients;

import com.iotmining.common.base.notifications.dto.BaseResponse;
import com.iotmining.common.base.notifications.dto.NotificationResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@FeignClient(name = "notificationClient", url = "${notification.service.url}")
public interface NotificationClient {

    @PostMapping("/api/notifications/internal/send")
    ResponseEntity<BaseResponse<NotificationResponse>> sendInternalPreReg(
            @RequestHeader("X-Internal-Token") String internalToken,
            @RequestHeader("X-Prospect-ID") String prospectId,
            @RequestBody Map<String, Object> body
    );

    @PostMapping("/api/notifications/send")
    ResponseEntity<BaseResponse<NotificationResponse>> sendWithTenant(
            @RequestHeader("Tenant-ID") String tenantId,
            @RequestHeader("X-User-ID") String userId,
            @RequestBody Map<String, Object> body
    );
}

