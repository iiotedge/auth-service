package com.iotmining.services.login_service.entity;

import java.time.LocalDateTime;
import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "user_login_data")
public class UserLoginData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;
    private String username;
    private String passwordSalt;
    private Integer hashAlgorithmId;
    private String confirmationToken;
    private LocalDateTime tokenGenerationTimestamp;
    private LocalDateTime tokenExpirationTime;
    private Integer emailValidationStatusId;
    private String passwordRecoveryToken;
    private Date recoveryTokenTime;
    private Boolean isUserLoggedIn;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "UserId", nullable = false)
    private User user;

}
