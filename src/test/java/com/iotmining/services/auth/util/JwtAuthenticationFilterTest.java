package com.iotmining.services.auth.util;

import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.security.UserPrincipal;
import com.iotmining.services.auth.services.CustomUserDetailsService;
import com.iotmining.services.auth.support.TestDataFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationFilter")
class JwtAuthenticationFilterTest {

    @Mock private CustomUserDetailsService customUserDetailsService;

    private JwtAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        TestDataFactory.initJwtProvider();
        SecurityContextHolder.clearContext();
        filter = new JwtAuthenticationFilter(customUserDetailsService);
        request = new MockHttpServletRequest("GET", "/api/v1/auth/tenants/x/users-list");
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("continues the chain unauthenticated when no Authorization header is present")
    void skipsWithoutAuthorizationHeader() throws Exception {
        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(filterChain.getRequest()).isNotNull(); // chain was invoked
        verify(customUserDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("ignores non-Bearer Authorization schemes")
    void skipsNonBearerHeader() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(customUserDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("authenticates the security context for a valid token")
    void authenticatesValidToken() throws Exception {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        when(customUserDetailsService.loadUserByUsername("john.doe")).thenReturn(new UserPrincipal(user));
        request.addHeader("Authorization", "Bearer " + JwtTokenProvider.generateAccessToken(user));

        filter.doFilter(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getPrincipal()).isInstanceOf(UserPrincipal.class);
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("does not authenticate when the token belongs to a different user")
    void rejectsMismatchedUser() throws Exception {
        User tokenOwner = TestDataFactory.user("john.doe", "ROLE_USER");
        User differentUser = TestDataFactory.user("jane.doe", "ROLE_USER");
        differentUser.setUsername("jane.doe");
        // Simulates a poisoned lookup: the loaded details don't match the token subject
        when(customUserDetailsService.loadUserByUsername("john.doe"))
                .thenReturn(new UserPrincipal(differentUser));
        request.addHeader("Authorization", "Bearer " + JwtTokenProvider.generateAccessToken(tokenOwner));

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("swallows malformed tokens and continues the chain unauthenticated")
    void toleratesMalformedToken() throws Exception {
        request.addHeader("Authorization", "Bearer not.a.jwt");

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("does not authenticate with an expired token")
    void rejectsExpiredToken() throws Exception {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        TestDataFactory.initJwtProvider(-5, -5);
        String expired = JwtTokenProvider.generateAccessToken(user);
        TestDataFactory.initJwtProvider();
        request.addHeader("Authorization", "Bearer " + expired);

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(customUserDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("preserves an already-authenticated security context")
    void preservesExistingAuthentication() throws Exception {
        Authentication existing = new UsernamePasswordAuthenticationToken("pre-authenticated", null);
        SecurityContextHolder.getContext().setAuthentication(existing);
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        request.addHeader("Authorization", "Bearer " + JwtTokenProvider.generateAccessToken(user));

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existing);
        verify(customUserDetailsService, never()).loadUserByUsername(anyString());
    }
}
