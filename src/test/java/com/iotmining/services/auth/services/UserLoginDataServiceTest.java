package com.iotmining.services.auth.services;

import com.iotmining.services.auth.dto.UserLoginDataDTO;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.entity.UserLoginData;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import com.iotmining.services.auth.support.TestDataFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserLoginDataService")
class UserLoginDataServiceTest {

    @Mock private UserLoginDataRepository userLoginDataRepository;

    @InjectMocks private UserLoginDataService userLoginDataService;

    @Test
    @DisplayName("persists the login event mapped from the DTO")
    void persistsLoginEvent() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime expiresAt = issuedAt.plusMinutes(30);
        UserLoginDataDTO dto = new UserLoginDataDTO(user.getUserId(), null, null, "jwt-token",
                issuedAt, expiresAt, null, null, null, true, user);

        userLoginDataService.addUserAsyncLoginData(dto);

        ArgumentCaptor<UserLoginData> captor = ArgumentCaptor.forClass(UserLoginData.class);
        verify(userLoginDataRepository).save(captor.capture());
        UserLoginData saved = captor.getValue();
        assertThat(saved.getAccessToken()).isEqualTo("jwt-token");
        assertThat(saved.getTokenGenerationTimestamp()).isEqualTo(issuedAt);
        assertThat(saved.getTokenExpirationTime()).isEqualTo(expiresAt);
        assertThat(saved.getIsUserLoggedIn()).isTrue();
        assertThat(saved.getUser()).isSameAs(user);
    }

    @Test
    @DisplayName("never lets a persistence failure break the login flow")
    void swallowsPersistenceFailure() {
        User user = TestDataFactory.user("john.doe", "ROLE_USER");
        UserLoginDataDTO dto = new UserLoginDataDTO(user.getUserId(), null, null, "jwt-token",
                LocalDateTime.now(), LocalDateTime.now().plusMinutes(30), null, null, null, true, user);
        when(userLoginDataRepository.save(any(UserLoginData.class)))
                .thenThrow(new RuntimeException("db down"));

        assertThatCode(() -> userLoginDataService.addUserAsyncLoginData(dto)).doesNotThrowAnyException();
    }
}
