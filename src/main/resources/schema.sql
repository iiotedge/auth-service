-- ShedLock's own lock table (see SchedulerLockConfig) - not a JPA entity,
-- so Hibernate's ddl-auto never creates it; this is the one schema object
-- in this service managed outside ddl-auto. Idempotent: safe on every boot.
CREATE TABLE IF NOT EXISTS shedlock (
    name       VARCHAR(64)  NOT NULL,
    lock_until TIMESTAMP    NOT NULL,
    locked_at  TIMESTAMP    NOT NULL,
    locked_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);
