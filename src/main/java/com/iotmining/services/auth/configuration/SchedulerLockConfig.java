package com.iotmining.services.auth.configuration;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * Makes @Scheduled jobs safe to run on more than one instance of this
 * service - without a lock, every replica runs TokenCleanupService's sweep
 * independently at the same moment, redundant DB load that scales with
 * instance count. ShedLock's JDBC provider stores the lock as a row in the
 * existing Postgres DB (see schema.sql for the shedlock table) - no new
 * infrastructure, and it fails safe: if a lock can't be acquired, the
 * scheduled method is simply skipped on that instance, never blocked.
 */
@Configuration
@EnableSchedulerLock(defaultLockAtMostFor = "PT10M")
public class SchedulerLockConfig {

    @Bean
    public LockProvider lockProvider(DataSource dataSource) {
        return new JdbcTemplateLockProvider(dataSource);
    }
}
