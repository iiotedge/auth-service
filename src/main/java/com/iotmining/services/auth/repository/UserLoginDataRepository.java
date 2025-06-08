package com.iotmining.services.auth.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.iotmining.services.auth.entity.UserLoginData;

@Repository
public interface UserLoginDataRepository extends JpaRepository<UserLoginData, UUID> {
    public Optional<UserLoginData> username(final String Username);

    // Find tokens that have expired
    List<UserLoginData> findByTokenExpirationTimeBefore(LocalDateTime now);

    // You can also add a method to delete expired tokens directly if needed
    void deleteByTokenExpirationTimeBefore(LocalDateTime now);
}