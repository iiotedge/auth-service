package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.Role;
import com.iotmining.services.auth.repository.RoleRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("RoleService")
class RoleServiceTest {

    @Mock private RoleRepository roleRepository;

    @InjectMocks private RoleService roleService;

    @Test
    @DisplayName("creates only the roles that do not exist yet")
    void createsMissingRolesOnly() {
        when(roleRepository.existsByName("ROLE_ADMIN")).thenReturn(true);
        when(roleRepository.existsByName("ROLE_USER")).thenReturn(false);

        roleService.insertRolesInAllShards(List.of("ROLE_ADMIN", "ROLE_USER"));

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository, times(1)).save(captor.capture());
        assertThat(captor.getValue().getName()).isEqualTo("ROLE_USER");
    }

    @Test
    @DisplayName("is idempotent when every role already exists")
    void idempotentWhenAllRolesExist() {
        when(roleRepository.existsByName(any())).thenReturn(true);

        roleService.insertRolesInAllShards(List.of("ROLE_ADMIN", "ROLE_USER"));

        verify(roleRepository, never()).save(any(Role.class));
    }

    @Test
    @DisplayName("continues with the remaining roles when one save fails")
    void continuesAfterSaveFailure() {
        when(roleRepository.existsByName(any())).thenReturn(false);
        when(roleRepository.save(any(Role.class)))
                .thenThrow(new RuntimeException("duplicate key"))
                .thenAnswer(invocation -> invocation.getArgument(0));

        assertThatCode(() -> roleService.insertRolesInAllShards(List.of("ROLE_ADMIN", "ROLE_USER")))
                .doesNotThrowAnyException();
        verify(roleRepository, times(2)).save(any(Role.class));
    }
}
