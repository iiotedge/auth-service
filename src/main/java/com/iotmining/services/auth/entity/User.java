package com.iotmining.services.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UuidGenerator;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_account")
public class User {
    @Id
    @UuidGenerator
    @Column(name = "user_id", updatable = false, nullable = false)
    private UUID userId;

    @Column(name = "tenant_id", unique = true)
    private UUID tenantId; // UUID as string from TMS

    @Column(unique = true)
    private String username;
    private String password;
    private String firstName;
    private String lastName;
    private String gender;
    private String dateOfBirth;
    private String email;
    private String phoneNumber;
    private Boolean isAccountActive;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<UserLoginData> userLoginData;
}


//package com.iotmining.services.auth.entity;
//
//import java.util.HashSet;
//import java.util.Set;
//import java.util.UUID;
//
//import jakarta.persistence.CascadeType;
//
//import static jakarta.persistence.CascadeType.ALL;
//
//import jakarta.persistence.Column;
//import jakarta.persistence.Entity;
//import jakarta.persistence.FetchType;
//import jakarta.persistence.GeneratedValue;
//import jakarta.persistence.GenerationType;
//import jakarta.persistence.Id;
//import jakarta.persistence.JoinColumn;
//import jakarta.persistence.JoinTable;
//import jakarta.persistence.ManyToMany;
//import jakarta.persistence.OneToMany;
//import jakarta.persistence.Table;
//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//import org.hibernate.annotations.UuidGenerator;
//
//@Data
//@NoArgsConstructor
//@AllArgsConstructor
//@Entity
//@Table(name = "user_account")
//public class User {
//    @Id
//    @UuidGenerator
//    @Column(name = "user_id", updatable = false, nullable = false)
//    private UUID userId;
//    @Column(name = "tenant_id", unique = true)
//    private UUID tenantId; // UUID as string from TMS
//    @Column(unique = true)
//    private String username;
//    private String password;
//    private String firstName;
//    private String lastName;
//    private String gender;
//    private String dateOfBirth;
//    private String email;
//    private String phoneNumber;
//    private Boolean isAccountActive;
//
//    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
//    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
//    private Set<Role> roles = new HashSet<>();
//
//    @OneToMany(fetch = FetchType.LAZY, mappedBy = "user", cascade = ALL, orphanRemoval = true)
//    private Set<UserLoginData> userLoginData;
//
//}
