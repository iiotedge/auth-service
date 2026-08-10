package com.iotmining.services.auth.services;

import java.util.*;
import java.util.stream.Collectors;

import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.entity.UserLoginData;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import com.iotmining.services.auth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
@RolesAllowed({"ROLE_SUPER_ADMIN"})
public class AdminPanelService {

    private final UserLoginDataRepository userLoginDataRepository;
    private final UserRepository userRepository;
    private final RestTemplate restTemplate;

    @Value("${tenant.service.url}")
    private String tmsServiceUrl; // e.g. http://localhost:8082/api/v1/tenants


    public AdminPanelService(UserLoginDataRepository userLoginDataRepository,
                             UserRepository userRepository,
                             RestTemplate restTemplate) {
        this.userLoginDataRepository = userLoginDataRepository;
        this.userRepository = userRepository;
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> revokeUserAccess(UUID userId, Boolean status) {
        UserLoginData user = userLoginDataRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        userRepository.updateUserStatus(userId, status);
        userLoginDataRepository.delete(user);
        return getTuplesWithPagination(0, 10);
    }

    public Map<String, Object> getTuplesWithPagination(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);

        Map<String, Object> response = new HashMap<>();
        Page<Map<String, Object>> userPage = userRepository.findAllUsers(pageable);

        if (userPage == null) {
            throw new RuntimeException("No data found");
        }

        response.put("data", userPage.getContent());
        return response;
    }

    public Map<String, Object> getCompaniesWithUsersAndDetails(UUID tenantId) {
        String url = tmsServiceUrl + "/" + tenantId + "/companies-with-users";
        Map<String, Object> response = new HashMap<>();
        try {
            // Fetch companies tree from TMS
            List<Map<String, Object>> companies = restTemplate.getForObject(url, List.class);
            if (companies == null) companies = Collections.emptyList();

            // Step 1: Extract all userIds from the companies tree
            Set<UUID> userIds = new HashSet<>();
            extractUserIdsSafe(companies, userIds);

            // Step 2: Fetch all user details from auth service
            List<User> users = userRepository.findAllById(userIds);

            // Step 3: Map userId -> User DTO
            Map<UUID, User> userMap = users.stream().collect(Collectors.toMap(User::getUserId, u -> u));

            // Step 4: Recursively enrich companies tree with user details
            enrichUserDetailsSafe(companies, userMap);

            response.put("tenantId", tenantId);
            response.put("companies", companies);
            response.put("statusCode", 200);
            response.put("message", "Success");
            return response;
        } catch (Exception e) {
            response.put("tenantId", tenantId);
            response.put("companies", Collections.emptyList());
            response.put("statusCode", 500);
            response.put("message", "Error: " + e.getMessage());
            return response;
        }
    }

    // Helper to extract all userIds from companies and subCompanies (SAFE!)
    private void extractUserIdsSafe(List<Map<String, Object>> companies, Set<UUID> userIds) {
        if (companies == null) return;
        for (Map<String, Object> company : companies) {
            if (company == null) continue;
            Object usersObj = company.get("users");
            if (usersObj instanceof List<?>) {
                for (Object userObj : (List<?>) usersObj) {
                    if (userObj instanceof Map) {
                        Map<?, ?> userMap = (Map<?, ?>) userObj;
                        Object userIdObj = userMap.get("userId");
                        if (userIdObj != null) {
                            try {
                                UUID userId = UUID.fromString(userIdObj.toString());
                                userIds.add(userId);
                            } catch (Exception ignore) {
                            }
                        }
                    }
                }
            }
            // Recursively for subCompanies
            Object subCompaniesObj = company.get("subCompanies");
            if (subCompaniesObj instanceof List<?>) {
                extractUserIdsSafe((List<Map<String, Object>>) subCompaniesObj, userIds);
            }
        }
    }

    // Helper to enrich each user node with user details (SAFE!)
    private void enrichUserDetailsSafe(List<Map<String, Object>> companies, Map<UUID, User> userMap) {
        if (companies == null) return;
        for (Map<String, Object> company : companies) {
            if (company == null) continue;
            Object usersObj = company.get("users");
            if (usersObj instanceof List<?>) {
                for (Object userObj : (List<?>) usersObj) {
                    if (userObj instanceof Map) {
                        Map<String, Object> user = (Map<String, Object>) userObj;
                        Object userIdObj = user.get("userId");
                        if (userIdObj != null) {
                            try {
                                UUID userId = UUID.fromString(userIdObj.toString());
                                User userDetails = userMap.get(userId);
                                if (userDetails != null) {
                                    user.put("username", userDetails.getUsername());
                                    user.put("email", userDetails.getEmail());
                                    user.put("phoneNumber", userDetails.getPhoneNumber());
                                    user.put("accountStatus", userDetails.getIsAccountActive());
                                    user.put("firstName", userDetails.getFirstName());
                                    user.put("lastName", userDetails.getLastName());
                                    // Add other fields as needed
                                }
                            } catch (Exception e) {
                                log.debug("Skipping malformed user node while enriching company tree: {}", e.getMessage());
                            }
                        }
                    }
                }
            }
            // Recursively for subCompanies
            Object subCompaniesObj = company.get("subCompanies");
            if (subCompaniesObj instanceof List<?>) {
                enrichUserDetailsSafe((List<Map<String, Object>>) subCompaniesObj, userMap);
            }
        }
    }
}
