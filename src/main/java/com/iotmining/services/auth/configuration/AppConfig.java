package com.iotmining.services.auth.configuration;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;

@Configuration
@Log4j2
public class AppConfig {

    @PostConstruct
    public void initialize() {
        log.info("Beans Constructed...");
    }
}
