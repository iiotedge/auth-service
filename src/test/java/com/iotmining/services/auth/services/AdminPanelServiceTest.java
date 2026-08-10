package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.entity.UserLoginData;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import com.iotmining.services.auth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("AdminPanelService")
class AdminPanelServiceTest {

    @Mock
    private UserLoginDataRepository userLoginDataRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private RestTemplate restTemplate;

    private AdminPanelService service;

    @BeforeEach
    void setUp() {
        service = new AdminPanelService(userLoginDataRepository, userRepository, restTemplate);
        ReflectionTestUtils.setField(service, "tmsServiceUrl", "http://tms/api/v1/tenants");
    }

    @Nested
    @DisplayName("revokeUserAccess")
    class RevokeUserAccess {

        @Test
        @DisplayName("updates status, deletes login data, and returns the refreshed page")
        void revokesAccessSuccessfully() {
            UUID userId = UUID.randomUUID();
            UserLoginData loginData = new UserLoginData();
            when(userLoginDataRepository.findById(userId)).thenReturn(Optional.of(loginData));
            when(userRepository.findAllUsers(any())).thenReturn(new PageImpl<>(List.of(Map.of("username", "a"))));

            Map<String, Object> result = service.revokeUserAccess(userId, false);

            verify(userRepository).updateUserStatus(userId, false);
            verify(userLoginDataRepository).delete(loginData);
            assertThat(result).containsKey("data");
        }

        @Test
        @DisplayName("throws EntityNotFoundException when the user's login data doesn't exist")
        void throwsWhenUserNotFound() {
            UUID userId = UUID.randomUUID();
            when(userLoginDataRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.revokeUserAccess(userId, true))
                    .isInstanceOf(EntityNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("getTuplesWithPagination")
    class GetTuplesWithPagination {

        @Test
        @DisplayName("wraps the repository page content under 'data'")
        void returnsPagedData() {
            when(userRepository.findAllUsers(any())).thenReturn(new PageImpl<>(List.of(Map.of("username", "a"))));

            Map<String, Object> result = service.getTuplesWithPagination(0, 10);

            assertThat((List<?>) result.get("data")).hasSize(1);
        }

        @Test
        @DisplayName("throws when the repository returns a null page")
        void throwsWhenPageIsNull() {
            when(userRepository.findAllUsers(any())).thenReturn(null);

            assertThatThrownBy(() -> service.getTuplesWithPagination(0, 10))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("No data found");
        }
    }

    @Nested
    @DisplayName("getCompaniesWithUsersAndDetails")
    class GetCompaniesWithUsersAndDetails {

        @Test
        @DisplayName("enriches nested company/subCompany user nodes with local user details")
        @SuppressWarnings("unchecked")
        void enrichesNestedTree() {
            UUID tenantId = UUID.randomUUID();
            UUID userId1 = UUID.randomUUID();
            UUID userId2 = UUID.randomUUID();

            Map<String, Object> subUser = new HashMap<>();
            subUser.put("userId", userId2.toString());

            Map<String, Object> subCompany = new HashMap<>();
            subCompany.put("companyId", "sub-1");
            subCompany.put("users", new ArrayList<>(List.of(subUser)));

            Map<String, Object> topUser = new HashMap<>();
            topUser.put("userId", userId1.toString());

            Map<String, Object> topCompanyWithBadUser = new HashMap<>();
            Map<String, Object> malformedUser = new HashMap<>();
            malformedUser.put("userId", "not-a-uuid");

            Map<String, Object> topCompany = new HashMap<>();
            topCompany.put("companyId", "top-1");
            topCompany.put("users", new ArrayList<>(List.of(topUser, malformedUser)));
            topCompany.put("subCompanies", new ArrayList<>(List.of(subCompany)));

            List<Map<String, Object>> companies = new ArrayList<>();
            companies.add(topCompany);
            // A null entry and a non-list "users" value both exercise defensive branches.
            companies.add(null);

            when(restTemplate.getForObject(eq("http://tms/api/v1/tenants/" + tenantId + "/companies-with-users"), eq(List.class)))
                    .thenReturn((List) companies);

            User user1 = new User();
            user1.setUserId(userId1);
            user1.setUsername("alice");
            user1.setEmail("alice@example.com");
            user1.setIsAccountActive(true);
            User user2 = new User();
            user2.setUserId(userId2);
            user2.setUsername("bob");

            when(userRepository.findAllById(any())).thenReturn(List.of(user1, user2));

            Map<String, Object> result = service.getCompaniesWithUsersAndDetails(tenantId);

            assertThat(result.get("statusCode")).isEqualTo(200);
            assertThat(result.get("tenantId")).isEqualTo(tenantId);
            assertThat(topUser.get("username")).isEqualTo("alice");
            assertThat(subUser.get("username")).isEqualTo("bob");
            // Malformed userId left un-enriched, not a failure.
            assertThat(malformedUser.get("username")).isNull();
        }

        @Test
        @DisplayName("returns a 500-shaped payload when the TMS call fails")
        void returnsErrorPayloadOnFailure() {
            UUID tenantId = UUID.randomUUID();
            when(restTemplate.getForObject(anyString(), eq(List.class))).thenThrow(new RuntimeException("TMS down"));

            Map<String, Object> result = service.getCompaniesWithUsersAndDetails(tenantId);

            assertThat(result.get("statusCode")).isEqualTo(500);
            assertThat((List<?>) result.get("companies")).isEmpty();
        }

        @Test
        @DisplayName("treats a null TMS response as an empty company list")
        void handlesNullTmsResponse() {
            UUID tenantId = UUID.randomUUID();
            when(restTemplate.getForObject(anyString(), eq(List.class))).thenReturn(null);
            when(userRepository.findAllById(any())).thenReturn(List.of());

            Map<String, Object> result = service.getCompaniesWithUsersAndDetails(tenantId);

            assertThat(result.get("statusCode")).isEqualTo(200);
            assertThat((List<?>) result.get("companies")).isEmpty();
        }
    }
}
