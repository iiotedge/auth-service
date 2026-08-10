package com.iotmining.services.auth.security;

import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.support.TestDataFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("UserPrincipal")
class UserPrincipalTest {

    @Test
    @DisplayName("exposes each role as a granted authority")
    void mapsRolesToAuthorities() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER", "ROLE_ADMIN");

        UserPrincipal principal = new UserPrincipal(user);

        assertThat(principal.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("delegates username and password to the entity")
    void delegatesCredentials() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");

        UserPrincipal principal = new UserPrincipal(user);

        assertThat(principal.getUsername()).isEqualTo(user.getUsername());
        assertThat(principal.getPassword()).isEqualTo(user.getPassword());
    }

    @Test
    @DisplayName("is enabled only when the account is explicitly active")
    void enabledOnlyWhenActive() {
        User active = TestDataFactory.user("active.user", "ROLE_USER");
        User disabled = TestDataFactory.user("disabled.user", "ROLE_USER");
        disabled.setIsAccountActive(false);
        User undecided = TestDataFactory.user("undecided.user", "ROLE_USER");
        undecided.setIsAccountActive(null); // must not NPE and must fail closed

        assertThat(new UserPrincipal(active).isEnabled()).isTrue();
        assertThat(new UserPrincipal(disabled).isEnabled()).isFalse();
        assertThat(new UserPrincipal(undecided).isEnabled()).isFalse();
    }

    @Test
    @DisplayName("never expires and credentials never expire")
    void accountFlagsAlwaysTrue() {
        UserPrincipal principal = new UserPrincipal(TestDataFactory.user("john.doe", "ROLE_USER"));

        assertThat(principal.isAccountNonExpired()).isTrue();
        assertThat(principal.isCredentialsNonExpired()).isTrue();
    }

    @Test
    @DisplayName("is unlocked when lockedUntil is unset")
    void unlockedWhenLockedUntilIsNull() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        user.setLockedUntil(null);

        assertThat(new UserPrincipal(user).isAccountNonLocked()).isTrue();
    }

    @Test
    @DisplayName("is unlocked once lockedUntil is in the past")
    void unlockedWhenLockExpired() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        user.setLockedUntil(Instant.now().minus(1, ChronoUnit.MINUTES));

        assertThat(new UserPrincipal(user).isAccountNonLocked()).isTrue();
    }

    @Test
    @DisplayName("is locked while lockedUntil is in the future")
    void lockedWhileLockedUntilIsFuture() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));

        assertThat(new UserPrincipal(user).isAccountNonLocked()).isFalse();
    }
}
