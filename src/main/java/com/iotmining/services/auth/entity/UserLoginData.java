package com.iotmining.services.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Entity
@Getter
@Setter
@Table(name = "user_login_data")
public class UserLoginData {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

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

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "userId", referencedColumnName = "user_id", nullable = false)
    private User user;
}

//package com.iotmining.services.auth.entity;
//
//import java.time.LocalDateTime;
//import java.util.Date;
//import java.util.UUID;
//
//import jakarta.persistence.*;
//import lombok.Getter;
//import lombok.Setter;
//import org.hibernate.annotations.UuidGenerator;
//
//@Entity
//@Getter
//@Setter
//@Table(name = "user_login_data")
//public class UserLoginData {
//
//    @Id
//    @UuidGenerator
//    @Column(name = "id", updatable = false, nullable = false)
//    private UUID id;
//    private String username;
//    private String passwordSalt;
//    private Integer hashAlgorithmId;
//    private String confirmationToken;
//    private LocalDateTime tokenGenerationTimestamp;
//    private LocalDateTime tokenExpirationTime;
//    private Integer emailValidationStatusId;
//    private String passwordRecoveryToken;
//    private Date recoveryTokenTime;
//    private Boolean isUserLoggedIn;
//
//    @ManyToOne
//    @JoinColumn(name = "user_id", referencedColumnName = "userId", nullable = false)
//    private User user;
//
//}
