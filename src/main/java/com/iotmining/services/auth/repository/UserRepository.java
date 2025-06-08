package com.iotmining.services.auth.repository;

import java.util.Map;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.iotmining.services.auth.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    User findByUsername(final String username);

    boolean existsByUsername(String username);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.isAccountActive = :status WHERE u.id = :userId")
    void updateUserStatus(@Param("userId") UUID userId, @Param("status") Boolean status);

    // @Query(value = "SELECT id AS userId, username, email, phoneNumber AS
    // phone_number, isAccountActive AS account_status FROM user_accout",
    // nativeQuery = true)
    @Query("SELECT u.userId AS id, u.username AS username, u.email AS email, u.phoneNumber AS phone_number, u.isAccountActive AS account_status FROM User u")
    Page<Map<String, Object>> findAllUsers(Pageable pageable);

}
