package com.iotmining.services.auth.aspect;

import lombok.extern.log4j.Log4j2;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Aspect
@Component
@Log4j2
public class LoggingAspect {

    @Before("execution(* com.iotmining.datafactory.auth.controller.AuthenticationController.*(..))")
    public void logBefore(JoinPoint joinPoint) {
        log.info("Executing method: {} with arguments: {}", joinPoint.getSignature().getName(), Arrays.toString(joinPoint.getArgs()));
    }

    @AfterReturning(value = "execution(* com.iotmining.datafactory.auth.controller.AuthenticationController.*(..))", returning = "result")
    public void logAfterReturning(JoinPoint joinPoint, Object result) {
        log.info("Method {} executed successfully with return value: {}", joinPoint.getSignature().getName(), result);
    }

    @AfterThrowing(value = "execution(* com.iotmining.datafactory.auth.controller.AuthenticationController.*(..))", throwing = "exception")
    public void logAfterThrowing(JoinPoint joinPoint, Exception exception) {
        log.error("Exception in method {} with message: {}", joinPoint.getSignature().getName(), exception.getMessage());
    }
}

