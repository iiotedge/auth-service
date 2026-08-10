package com.iotmining.services.auth.repository;

import com.iotmining.services.auth.entity.UserLoginData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.UUID;

@Repository
public interface UserLoginDataRepository extends JpaRepository<UserLoginData, UUID> {
    // Define the delete method signature
    // @Modifying is implied for derived delete methods in recent Spring versions,
    // but explicit @Transactional is usually handled at the Service level.
    void deleteByTokenExpirationTimeBefore(LocalDateTime time);
}

