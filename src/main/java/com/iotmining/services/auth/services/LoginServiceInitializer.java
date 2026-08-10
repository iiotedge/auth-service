package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.repository.RoleRepository;
import com.iotmining.services.auth.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class LoginServiceInitializer {

    private final RoleService roleService;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Same Constant used in TMS
    private static final UUID SYSTEM_TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    // No literal default for the password - a bootstrap credential that
    // ships as a source-code (or even a committed application.yml)
    // default is a real, standing credential leak the moment this repo
    // is pushed anywhere. Email has a default since a username/email on
    // its own isn't a secret; the password must be supplied per
    // environment (e.g. via SUPER_ADMIN_PASSWORD) or seeding is skipped.
    @Value("${admin.seed.email:santoshgndp@gmail.com}")
    private String seedAdminEmail;

    @Value("${admin.seed.password:}")
    private String seedAdminPassword;

    @PostConstruct
    @Transactional
    public void init() {
        log.info("Auth Boot: Initializing Data...");

        // 1. Initialize Roles
        roleService.insertRolesInAllShards(List.of(
                "ROLE_SUPER_ADMIN", "ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER"
        ));

        // 2. Initialize Super Admin User
        // NO NEED to check/create Tenant here. TMS handles that.
        createSuperAdmin();
    }

    private void createSuperAdmin() {
        if (userRepository.existsByUsername(seedAdminEmail)) {
            log.info("Auth Boot: Super Admin already exists.");
            return;
        }

        if (seedAdminPassword == null || seedAdminPassword.isBlank()) {
            log.warn("Auth Boot: admin.seed.password is not set - skipping Super Admin creation. "
                    + "Set the SUPER_ADMIN_PASSWORD environment variable to seed one.");
            return;
        }

        log.info("Auth Boot: Creating Super Admin...");

        Role superAdminRole = roleRepository.findByName("ROLE_SUPER_ADMIN")
                .orElseThrow(() -> new RuntimeException("Error: ROLE_SUPER_ADMIN missing."));

        User user = new User();
        user.setUsername(seedAdminEmail);
        user.setEmail(seedAdminEmail);
        user.setPassword(passwordEncoder.encode(seedAdminPassword));
        user.setFirstName("System");
        user.setLastName("Administrator");
        user.setIsAccountActive(true);

        // We blindly assign the known System Tenant ID.
        // We trust TMS has created (or will create) this record.
        user.setTenantId(SYSTEM_TENANT_ID);

        user.setRoles(Collections.singleton(superAdminRole));

        userRepository.save(user);
        log.info("Auth Boot: Super Admin Created.");
    }
}

