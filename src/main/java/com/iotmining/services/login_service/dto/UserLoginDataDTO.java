package com.iotmining.services.login_service.dto;

import java.time.LocalDateTime;
import java.util.Date;

import com.iotmining.services.login_service.entity.User;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserLoginDataDTO {

    private Long UserId;
    private String passwordSalt;
    private Integer hashAlgorithmId;
    private String confirmationToken;
    private LocalDateTime tokenGenerationTimestamp;
    private LocalDateTime tokenExpirationTime;
    private Integer emailValidationStatusId;
    private String passwordRecoveryToken;
    private Date recoveryTokenTime;
    private Boolean isUserLoggedIn;
    private User user;
}
