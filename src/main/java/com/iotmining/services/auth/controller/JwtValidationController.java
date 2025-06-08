package com.iotmining.services.auth.controller;

import com.iotmining.services.auth.util.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/validate")
public class JwtValidationController {

    @GetMapping
    public ResponseEntity<?> validate(HttpServletRequest request) {
        String token = extractToken(request);
        if (token == null || !JwtTokenProvider.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Claims claims = JwtTokenProvider.extractAllClaims(token);
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-User-Id", claims.getSubject());
        headers.set("X-Tenant-Id", claims.get("tenantId", String.class));
        headers.set("X-Parent-Org-Id", claims.get("parentOrganizationId", String.class));

        return ResponseEntity.ok().headers(headers).build();
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return (header != null && header.startsWith("Bearer "))
                ? header.substring(7)
                : null;
    }
}
