package com.iotmining.services.login_service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value = "/api/v1")
public class HomeController {
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @RolesAllowed({ "ROLE_ADMIN", "ROLE_SUPER_ADMIN" })
    @GetMapping("/admin")
    public ResponseEntity<String> helloAdmin() {
        return ResponseEntity.ok("Hello Admin");
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @RolesAllowed({ "ROLE_USER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN" })
    @GetMapping("/user")
    public ResponseEntity<String> helloUser() {
        return ResponseEntity.ok("Hello User");
    }

    @GetMapping("/all")
    public String allAccess() {
        return "Public Content";
    }

    @GetMapping("/")
    public String home(HttpServletRequest request) {
        return "Welcome Home : "+ request.getSession().getId();
    }
}
