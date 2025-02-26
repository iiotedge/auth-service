package com.iotmining.services.login_service.services;

import java.time.LocalDateTime;

import com.iotmining.services.login_service.repository.UserLoginDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
// import repository.com.iotmining.services.login_service.UserLoginDataRepository;

@Service
public class TokenCleanupService {

    @Autowired
     private UserLoginDataRepository tokenRepository;

    @Async
    @Scheduled(fixedRate = 30000) // Run every 60 seconds (1 minute)
    public void removeExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();

////         Option 1: Find expired tokens and delete them individually
//         List<UserLoginData> expiredTokens = tokenRepository.findByTokenExpirationTimeBefore(now);
//         if (!expiredTokens.isEmpty()) {
//             tokenRepository.deleteAll(expiredTokens);
//         }

//         Option 2: Delete expired tokens directly in the repository
         tokenRepository.deleteByTokenExpirationTimeBefore(now);

        System.out.println("Expired tokens removed at " + now);
    }
}
