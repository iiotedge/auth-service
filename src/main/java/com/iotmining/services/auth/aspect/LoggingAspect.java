package com.iotmining.services.auth.aspect;

import lombok.extern.log4j.Log4j2;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

/**
 * Method-name-only logging for AuthenticationController - deliberately
 * never logs arguments or return values, since almost every method here
 * carries a password (login/register) or a JWT/refresh token (login,
 * refresh, register/verify responses); logging those would leak
 * credentials into application logs.
 *
 * <p>The pointcut previously targeted a stale package
 * ({@code com.iotmining.datafactory.auth.controller}, a leftover from
 * before this service was renamed to {@code com.iotmining.services.auth})
 * and so never matched anything - this aspect was silently dead at runtime.
 */
@Aspect
@Component
@Log4j2
public class LoggingAspect {

    @Before("execution(* com.iotmining.services.auth.controller.AuthenticationController.*(..))")
    public void logBefore(JoinPoint joinPoint) {
        log.info("Executing method: {}", joinPoint.getSignature().getName());
    }

    @AfterReturning("execution(* com.iotmining.services.auth.controller.AuthenticationController.*(..))")
    public void logAfterReturning(JoinPoint joinPoint) {
        log.info("Method {} executed successfully", joinPoint.getSignature().getName());
    }

    @AfterThrowing(value = "execution(* com.iotmining.services.auth.controller.AuthenticationController.*(..))", throwing = "exception")
    public void logAfterThrowing(JoinPoint joinPoint, Exception exception) {
        log.error("Exception in method {} with message: {}", joinPoint.getSignature().getName(), exception.getMessage());
    }
}

