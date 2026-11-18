//package com.iotmining.services.auth.configuration;
//
//import com.iotmining.services.auth.entity.Role;
//import com.iotmining.services.auth.entity.User;
//import com.iotmining.services.auth.repository.RoleRepository;
//import com.iotmining.services.auth.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.log4j.Log4j2;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.Collections;
//import java.util.UUID;
//
//@Component
//@RequiredArgsConstructor
//@Log4j2
//public class AdminSeeder implements CommandLineRunner {
//
//    private final UserRepository userRepository;
//    private final RoleRepository roleRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    // Standard "System" Tenant ID (Zero UUID)
//    // Since the Tenant Service is separate, we use this ID to represent the platform owner.
//    private static final UUID SYSTEM_TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000000");
//
//    @Override
//    @Transactional
//    public void run(String... args) throws Exception {
//        // 1. Ensure Roles Exist
//        Role superAdminRole = createRoleIfNotFound("ROLE_SUPER_ADMIN");
//        createRoleIfNotFound("ROLE_ADMIN");
//        createRoleIfNotFound("ROLE_USER");
//
//        // 2. Create Super Admin
//        createSuperAdmin(superAdminRole);
//    }
//
//    private void createSuperAdmin(Role superAdminRole) {
//        String email = "santoshgndp@gmail.com";
//
//        // Check if exists to prevent duplicates on restart
//        if (userRepository.existsByUsername(email)) {
//            log.info("System Boot: Super Admin account already exists.");
//            return;
//        }
//
//        log.info("System Boot: Creating initial Super Admin account...");
//
//        User user = new User();
//        // ID is handled by @UuidGenerator, so we don't set it manually unless needed
//
//        user.setUsername(email);
//        user.setEmail(email);
//        user.setPassword(passwordEncoder.encode("Gndp8506@")); // <--- CHANGE THIS ON FIRST LOGIN
//
//        user.setFirstName("System");
//        user.setLastName("Administrator");
//        user.setIsAccountActive(true); // Matching your entity field name
//
//        // CRITICAL: We set the Tenant ID to the "Zero UUID"
//        // This tells the frontend/backend that this user belongs to the System, not a specific customer.
//        user.setTenantId(SYSTEM_TENANT_ID);
//
//        user.setRoles(Collections.singleton(superAdminRole));
//
//        userRepository.save(user);
//        log.info("----------------------------------------------------------");
//        log.info("SUPER ADMIN CREATED");
//        log.info("Username: {}", email);
//        log.info("Password: Gndp8506@");
//        log.info("TenantID: {}", SYSTEM_TENANT_ID);
//        log.info("----------------------------------------------------------");
//    }
//
//    private Role createRoleIfNotFound(String name) {
//        return roleRepository.findByName(name)
//                .orElseGet(() -> {
//                    Role role = new Role();
//                    role.setName(name);
//                    return roleRepository.save(role);
//                });
//    }
//}