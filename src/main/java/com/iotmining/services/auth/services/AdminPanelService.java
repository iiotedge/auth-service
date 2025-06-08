package com.iotmining.services.auth.services;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.iotmining.services.auth.entity.UserLoginData;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import com.iotmining.services.auth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

// import repository.com.iotmining.datafactory.auth.UserLoginDataRepository;
// import repository.com.iotmining.datafactory.auth.UserRepository;

import jakarta.annotation.security.RolesAllowed;

@Service
@RolesAllowed({"ROLE_SUPER_ADMIN"})
public class AdminPanelService {

    @Autowired
    UserLoginDataRepository userLoginDataRepository;
    @Autowired
    private UserRepository adminPanelRepository;

    public Map<String, Object> revokeUserAccess(UUID userId, Boolean status) {
        UserLoginData user = userLoginDataRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        adminPanelRepository.updateUserStatus(userId, status);
        userLoginDataRepository.delete(user);
        return getTuplesWithPagination(0, 10);
    }

    public Map<String, Object> getTuplesWithPagination(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);

        Map<String, Object> response = new HashMap<>();
        Page<Map<String, Object>> userPage = adminPanelRepository.findAllUsers(pageable);

        if (userPage == null) {
            throw new RuntimeException("No data found");
        }

        response.put("data", userPage.getContent());
        return response;
    }
}
