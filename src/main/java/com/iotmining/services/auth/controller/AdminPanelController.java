package com.iotmining.services.auth.controller;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import com.iotmining.services.auth.dto.UserCredentialDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.iotmining.services.auth.services.AdminPanelService;

import jakarta.annotation.security.RolesAllowed;

@RestController
@RequestMapping(value = "/api/v1/super-admin")
//@PreAuthorize("hasRole('SUPER_ADMIN')")
//@RolesAllowed({"SUPER_ADMIN"})
public class AdminPanelController {

    @Autowired
    AdminPanelService adminPanelService;

    @GetMapping("/getUserDetails")
    @RolesAllowed({"SUPER_ADMIN"})
    public ResponseEntity<Map<String, Object>> getUserDetails(@RequestParam("page") int page, @RequestParam("size") int size) {
        Map<String, Object> response = adminPanelService.getTuplesWithPagination(page, size);
        if (response == null) {
            response = Collections.emptyMap();
        }
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/removeUser")
    public ResponseEntity<String> removeUser(@RequestBody UserCredentialDTO userDetails) {
        return ResponseEntity.ok("Admin Panel");
    }

    @GetMapping("/revokeUser")
    public Map<String, Object> revokeUserAccess(@RequestParam("user_id") UUID user_id,
                                                @RequestParam("status") Boolean status) {
        return adminPanelService.revokeUserAccess(user_id, status);
    }

    // --- New Endpoint ---
    @GetMapping("/tenant-companies-users-details")
//    @RolesAllowed({"SUPER_ADMIN"})
    public ResponseEntity<Map<String, Object>> getCompaniesWithUserDetails(
            @RequestParam("tenantId") UUID tenantId) {
        Map<String, Object> response = adminPanelService.getCompaniesWithUsersAndDetails(tenantId);
        if (response == null) {
            response = Collections.emptyMap();
        }
        return ResponseEntity.ok(response);
    }
}
