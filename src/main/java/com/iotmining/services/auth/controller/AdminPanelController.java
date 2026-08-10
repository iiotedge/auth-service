package com.iotmining.services.auth.controller;

import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.iotmining.services.auth.services.AdminPanelService;
import jakarta.annotation.security.RolesAllowed;

@RestController
@RequestMapping(value = "/api/v1/auth/super-admin")
public class AdminPanelController {

    @Autowired
    AdminPanelService adminPanelService;

    @GetMapping("/getUserDetails")
    @RolesAllowed({"ROLE_SUPER_ADMIN"})
    public ResponseEntity<Map<String, Object>> getUserDetails(@RequestParam("page") int page, @RequestParam("size") int size) {
        // getTuplesWithPagination never returns null - it throws instead.
        return ResponseEntity.ok(adminPanelService.getTuplesWithPagination(page, size));
    }

    // POST, not GET - this mutates account state (deactivates the user and
    // deletes their login data), so it must not be cacheable/prefetchable
    // and needs an explicit role check rather than relying solely on
    // AdminPanelService's class-level @RolesAllowed.
    @PostMapping("/revokeUser")
    @RolesAllowed({"ROLE_SUPER_ADMIN"})
    public Map<String, Object> revokeUserAccess(@RequestParam("user_id") UUID user_id,
                                                @RequestParam("status") Boolean status) {
        return adminPanelService.revokeUserAccess(user_id, status);
    }

    @GetMapping("/tenant-companies-users-details")
    @RolesAllowed({"ROLE_SUPER_ADMIN"})
    public ResponseEntity<Map<String, Object>> getCompaniesWithUserDetails(
            @RequestParam("tenantId") UUID tenantId) {
        // getCompaniesWithUsersAndDetails always returns a populated response,
        // even on failure (it puts statusCode/message onto the same map).
        return ResponseEntity.ok(adminPanelService.getCompaniesWithUsersAndDetails(tenantId));
    }
}
