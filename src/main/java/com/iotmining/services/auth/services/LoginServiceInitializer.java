package com.iotmining.services.auth.services;


import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;


@Component
public class LoginServiceInitializer {

    @Autowired
    private RoleService roleService;

    @PostConstruct
    public void init() {
        roleService.insertRolesInAllShards(List.of("ROLE_SUPER_ADMIN", "ROLE_ADMIN", "ROLE_USER"));
    }

}
