package com.iotmining.services.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UuidGenerator;

import java.util.UUID;

@Entity
@Data
@Table(name = "Role")
@NoArgsConstructor
public class Role {

    @Id
    @UuidGenerator
    @Column(name = "role_id", updatable = false, nullable = false)
    private UUID roleId;

    @Column(nullable = false, unique = true)
    private String name; // Standard practice is 'name' instead of 'roleName' for GrantedAuthority compatibility

    public Role(String name) {
        this.name = name;
    }
}

