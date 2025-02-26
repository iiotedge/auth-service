package com.iotmining.services.login_service.services;

import com.iotmining.services.login_service.dto.UserLoginDataDTO;
import com.iotmining.services.login_service.entity.UserLoginData;
import com.iotmining.services.login_service.repository.UserLoginDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class UserLoginDataService {

    @Autowired
    UserLoginDataRepository userLoginDataRepository;

    @Async
    public void addUserAsyncLoginData(UserLoginDataDTO request) {

        UserLoginData userLoginData = new UserLoginData();
        userLoginData.setUser(request.getUser());
        // user.setUserId(request.getUserId());
        userLoginData.setPasswordSalt(request.getPasswordSalt());
        userLoginData.setHashAlgorithmId(request.getHashAlgorithmId());
        userLoginData.setConfirmationToken(request.getConfirmationToken());
        userLoginData.setTokenExpirationTime(request.getTokenExpirationTime());
        userLoginData.setTokenGenerationTimestamp(request.getTokenGenerationTimestamp());
        userLoginData.setEmailValidationStatusId(request.getEmailValidationStatusId());
        userLoginData.setPasswordRecoveryToken(request.getPasswordRecoveryToken());
        userLoginData.setRecoveryTokenTime(request.getRecoveryTokenTime());
        userLoginData.setIsUserLoggedIn(request.getIsUserLoggedIn());

        userLoginDataRepository.save(userLoginData);
    }
}
