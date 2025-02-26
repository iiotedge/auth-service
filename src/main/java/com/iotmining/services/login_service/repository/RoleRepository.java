package com.iotmining.services.login_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.iotmining.services.login_service.entity.Role;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(String roleName);
}