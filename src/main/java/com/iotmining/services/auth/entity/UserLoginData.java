package com.iotmining.services.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UuidGenerator;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "user_login_data")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserLoginData {

    @Id
    @UuidGenerator
    private UUID id;

    @Column(length = 1000) // Tokens can be long
    private String accessToken; // Mapped from DTO's confirmationToken

    private LocalDateTime tokenGenerationTimestamp;
    private LocalDateTime tokenExpirationTime;

    private Boolean isUserLoggedIn;

    // Mapping back to User
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Optional audit fields
    private String ipAddress;
    private String deviceInfo;
}

