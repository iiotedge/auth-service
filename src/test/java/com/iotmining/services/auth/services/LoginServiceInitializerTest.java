package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.repository.RoleRepository;
import com.iotmining.services.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceInitializerTest {

    @Mock
    private RoleService roleService;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;

    private LoginServiceInitializer initializer;

    @BeforeEach
    void setUp() {
        initializer = new LoginServiceInitializer(roleService, roleRepository, userRepository, passwordEncoder);
        ReflectionTestUtils.setField(initializer, "seedAdminEmail", "admin@example.com");
    }

    @Test
    void skipsSeedingWhenSuperAdminAlreadyExists() {
        ReflectionTestUtils.setField(initializer, "seedAdminPassword", "SomePassword@1");
        when(userRepository.existsByUsername("admin@example.com")).thenReturn(true);

        initializer.init();

        verify(roleService).insertRolesInAllShards(anyList());
        verify(userRepository, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void skipsSeedingWhenNoPasswordConfigured() {
        ReflectionTestUtils.setField(initializer, "seedAdminPassword", "");
        when(userRepository.existsByUsername("admin@example.com")).thenReturn(false);

        initializer.init();

        verify(userRepository, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void seedsSuperAdminWhenPasswordIsConfigured() {
        ReflectionTestUtils.setField(initializer, "seedAdminPassword", "SomePassword@1");
        when(userRepository.existsByUsername("admin@example.com")).thenReturn(false);
        when(roleRepository.findByName("ROLE_SUPER_ADMIN")).thenReturn(Optional.of(new Role("ROLE_SUPER_ADMIN")));
        when(passwordEncoder.encode("SomePassword@1")).thenReturn("encoded-hash");

        initializer.init();

        ArgumentCaptor<com.iotmining.services.auth.entity.User> captor =
                ArgumentCaptor.forClass(com.iotmining.services.auth.entity.User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getUsername()).isEqualTo("admin@example.com");
        assertThat(captor.getValue().getPassword()).isEqualTo("encoded-hash");
    }

    @Test
    void throwsWhenSuperAdminRoleIsMissing() {
        ReflectionTestUtils.setField(initializer, "seedAdminPassword", "SomePassword@1");
        when(userRepository.existsByUsername("admin@example.com")).thenReturn(false);
        when(roleRepository.findByName("ROLE_SUPER_ADMIN")).thenReturn(Optional.empty());

        org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class, initializer::init);
    }
}
