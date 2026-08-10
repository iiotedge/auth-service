package com.iotmining.services.auth.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoggingAspectTest {

    private final LoggingAspect aspect = new LoggingAspect();

    @Mock
    private JoinPoint joinPoint;
    @Mock
    private Signature signature;

    @Test
    void logBeforeDoesNotThrow() {
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getName()).thenReturn("login");
        aspect.logBefore(joinPoint);
    }

    @Test
    void logAfterReturningDoesNotThrow() {
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getName()).thenReturn("login");
        aspect.logAfterReturning(joinPoint);
    }

    @Test
    void logAfterThrowingDoesNotThrow() {
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getName()).thenReturn("login");
        aspect.logAfterThrowing(joinPoint, new RuntimeException("boom"));
    }
}
