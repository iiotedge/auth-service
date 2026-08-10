package com.iotmining.services.auth.util;

import com.iotmining.services.auth.services.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String path = request.getServletPath();

        // 1. Check for Bearer Token
        if (path.contains("/auth/tenants/")) {
            log.info("Processing security for path: {} | Header present: {}", path, (authHeader != null));
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // If this logs, then your React app is NOT sending the token
            if (path.contains("/auth/tenants/")) {
                log.warn("Security check skipped: No Bearer token found in header for path {}", path);
            }
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);

        try {
            // 2. Extract Username
            final String username = JwtTokenProvider.extractUserName(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);

                // 3. Verify and Authenticate
                if (JwtTokenProvider.verifyToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Success Log: Traceable log for production audits
                    log.info("Successfully authenticated user [{}] for path [{}]", username, path);

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    log.warn("JWT Verification failed for user [{}] at path [{}]", username, path);
                }
            }
        } catch (Exception e) {
            // Production Error Log: Structured with exception details
            log.error("Authentication internal failure for path [{}]: {}", path, e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}

