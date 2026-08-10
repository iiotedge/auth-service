package com.iotmining.services.auth.controller;

import com.iotmining.services.auth.services.AdminPanelService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link AdminPanelController} using standalone MockMvc.
 * Authorization annotations are enforced by Spring Security at runtime and are
 * out of scope for a standalone setup.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AdminPanelController")
class AdminPanelControllerTest {

    @Mock private AdminPanelService adminPanelService;

    @InjectMocks private AdminPanelController controller;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("GET /getUserDetails returns the paginated user list")
    void getUserDetails() throws Exception {
        when(adminPanelService.getTuplesWithPagination(0, 10))
                .thenReturn(Map.of("data", List.of(Map.of("username", "john.doe"))));

        mockMvc.perform(get("/api/v1/auth/super-admin/getUserDetails")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].username").value("john.doe"));
    }

    @Test
    @DisplayName("POST /revokeUser delegates to the service with the parsed parameters")
    void revokeUser() throws Exception {
        UUID userId = UUID.randomUUID();
        when(adminPanelService.revokeUserAccess(userId, false)).thenReturn(Map.of("data", List.of()));

        mockMvc.perform(post("/api/v1/auth/super-admin/revokeUser")
                        .param("user_id", userId.toString())
                        .param("status", "false"))
                .andExpect(status().isOk());

        verify(adminPanelService).revokeUserAccess(userId, false);
    }

    @Test
    @DisplayName("GET /tenant-companies-users-details returns the enriched tree")
    void tenantCompaniesWithUsers() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(adminPanelService.getCompaniesWithUsersAndDetails(tenantId))
                .thenReturn(Map.of("statusCode", 200, "companies", List.of()));

        mockMvc.perform(get("/api/v1/auth/super-admin/tenant-companies-users-details")
                        .param("tenantId", tenantId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.statusCode").value(200));
    }
}
