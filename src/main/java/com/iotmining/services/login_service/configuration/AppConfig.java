package com.iotmining.services.login_service.configuration;

import org.springframework.context.annotation.Configuration;

//import com.codenaive.iot.dashboard.login_service.context.DataSourceContextHolder;

import jakarta.annotation.PostConstruct;

@Configuration
public class AppConfig {

    @PostConstruct
    public void initialize() {
        System.out.println("Beans Constructed...");
    }
}
