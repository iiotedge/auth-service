package com.iotmining.services.auth.repository;

import com.iotmining.services.auth.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Return Optional to prevent NullPointerExceptions in Service layer
    Optional<User> findByUsername(String username);

    // Standard existence checks
    boolean existsByUsername(String username);

    // NEW: Required for Internal User Creation (Invitation Flow)
    boolean existsByEmail(String email);

    @Modifying
    @Transactional
    // FIX: Changed "u.id" to "u.userId" to match your User entity field name
    @Query("UPDATE User u SET u.isAccountActive = :status WHERE u.userId = :userId")
    void updateUserStatus(@Param("userId") UUID userId, @Param("status") Boolean status);

    // Projection Query (Fixed aliases for consistency)
    @Query("SELECT u.userId AS id, u.username AS username, u.email AS email, " +
            "u.phoneNumber AS phoneNumber, u.isAccountActive AS accountStatus " +
            "FROM User u")
    Page<Map<String, Object>> findAllUsers(Pageable pageable);

    @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
    Optional<User> findByUsernameOrEmail(@Param("input") String input);

    List<User> findByTenantId(UUID tenantId);

}

