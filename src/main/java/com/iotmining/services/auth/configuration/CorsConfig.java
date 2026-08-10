package com.iotmining.services.auth.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
public class CorsConfig {

    /**
     * DEVELOPMENT BEAN
     * Active only when -Dspring.profiles.active=dev
     * Allows all local ports and wildcards for easy debugging.
     */
    @Bean
    @Profile("dev")
    @Primary
    public CorsConfigurationSource devCorsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 1. Permissive local patterns
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:3000",
                "http://localhost:3001",
                "http://localhost:3002",
//                "http://127.0.0.1:*",
//                "https://*.iiotedge.in",
//                "http://*.iiotedge.in
//
                "https://*.iiotedge.in",
                "https://iiotedge.in"
        ));

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Collections.singletonList("*"));
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-User-Id",
                "X-Tenant-Id",
                "X-User-Roles"
        ));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // Cache preflight for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * PRODUCTION BEAN
     * Active only when -Dspring.profiles.active=prod
     *
     * auth-service is the one service whose Nginx location block
     * (see iiotedge-cli.sh, "/api/v1/auth") does NOT include the shared
     * iiotedge_cors.conf snippet that every other proxied service gets —
     * so this is the only CORS enforcement layer for login/register/etc.
     * in production. Origins/methods/headers below mirror that same
     * shared Nginx CORS policy (iiotedge-cli.sh: DOMAIN_APEX, DOMAIN_DASHBOARD,
     * and the iiotedge_cors.conf allow-list) so behavior stays consistent
     * with every other service on the platform.
     */
    @Bean
    @Profile("prod")
    @Primary
    public CorsConfigurationSource prodCorsConfigurationSource(
            @Value("${cors.allowed-origins:https://iiotedge.in,https://demo.iiotedge.in,http://localhost:3000}")
            String allowedOrigins) {
        CorsConfiguration configuration = new CorsConfiguration();

        List<String> origins = Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .toList();
        configuration.setAllowedOriginPatterns(origins);

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-Requested-With",
                "X-Auth-Token",
                "X-Correlation-ID"
        ));
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "X-User-Id",
                "X-Tenant-Id",
                "X-User-Roles"
        ));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

