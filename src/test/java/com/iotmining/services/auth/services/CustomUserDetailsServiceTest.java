package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.repository.UserRepository;
import com.iotmining.services.auth.security.UserPrincipal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    private CustomUserDetailsService service;

    @Test
    void loadsUserByUsernameOrEmail() {
        service = new CustomUserDetailsService(userRepository);
        User user = new User();
        user.setUserId(UUID.randomUUID());
        user.setUsername("john.doe");
        when(userRepository.findByUsernameOrEmail("john.doe")).thenReturn(Optional.of(user));

        UserDetails result = service.loadUserByUsername("john.doe");

        assertThat(result).isInstanceOf(UserPrincipal.class);
        assertThat(((UserPrincipal) result).getUser()).isSameAs(user);
    }

    @Test
    void throwsWhenNoMatchingUser() {
        service = new CustomUserDetailsService(userRepository);
        when(userRepository.findByUsernameOrEmail("nobody")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUserByUsername("nobody"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
