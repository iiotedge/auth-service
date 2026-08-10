package com.iotmining.services.auth.services;

import com.iotmining.services.auth.dto.UserLoginDataDTO;
import com.iotmining.services.auth.entity.UserLoginData;
import com.iotmining.services.auth.repository.UserLoginDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserLoginDataService {

    private final UserLoginDataRepository userLoginDataRepository;

    /**
     * Async method to log login events.
     * Uses REQUIRES_NEW propagation to ensure it commits even if the main transaction rolls back (optional choice).
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void addUserAsyncLoginData(UserLoginDataDTO dto) {
        try {
            UserLoginData entity = new UserLoginData();
            entity.setAccessToken(dto.getConfirmationToken());
            entity.setTokenGenerationTimestamp(dto.getTokenGenerationTimestamp());
            entity.setTokenExpirationTime(dto.getTokenExpirationTime());
            entity.setIsUserLoggedIn(dto.getIsUserLoggedIn());
            entity.setUser(dto.getUser());

            userLoginDataRepository.save(entity);
            log.debug("Async login data saved for user: {}", dto.getUser().getUsername());

        } catch (Exception e) {
            // We catch exceptions here because we don't want a logging failure
            // to crash the user's login experience.
            log.error("Failed to save async login data", e);
        }
    }
}

