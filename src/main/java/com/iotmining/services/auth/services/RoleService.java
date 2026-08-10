package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class RoleService {

    private final RoleRepository roleRepository;

    @Transactional
    public void insertRolesInAllShards(List<String> roles) {
        for (String roleName : roles) {
            if (!roleRepository.existsByName(roleName)) {
                try {
                    roleRepository.save(new Role(roleName));
                    log.info("Initialized role: {}", roleName);
                } catch (Exception e) {
                    log.error("Failed to initialize role: {}", roleName, e);
                }
            }
        }
    }
}

