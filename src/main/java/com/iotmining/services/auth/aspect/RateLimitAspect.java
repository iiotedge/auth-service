package com.iotmining.services.auth.aspect;

import com.iotmining.services.auth.exceptions.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Aspect
@Component
/*
 * Description:  Using Sliding window rate limit with ip address from header.
 */
public class RateLimitAspect {

    @Autowired
    private StringRedisTemplate redisTemplate;

    // Configuration properties for max requests and time window
    @Value("${rate.limit.max-requests:5}")  // Default 5 requests per minute
    private int maxRequests;

    @Value("${rate.limit.time-window:1}")  // Default time window of 1 minute
    private long timeWindow;

    @Value("${rate.limit.error-message:Rate limit exceeded, please try again later}")
    private String errorMessage;

    private static final String RATE_LIMIT_PREFIX = "rate_limit:";

    @Around("@annotation(com.iotmining.services.auth.annotation.RateLimited)")
    public Object rateLimit(ProceedingJoinPoint joinPoint) throws Throwable {
        String ip = getClientIp();
        String key = RATE_LIMIT_PREFIX + ip;

        long currentTime = System.currentTimeMillis();
        long timeWindowStart = currentTime - TimeUnit.MINUTES.toMillis(timeWindow); // Time window start

        // Remove timestamps older than the time window
        redisTemplate.opsForZSet().removeRangeByScore(key, 0, timeWindowStart);

        // Get the count of requests within the time window
        Long requestCount = redisTemplate.opsForZSet().count(key, timeWindowStart, currentTime);

        if (requestCount != null && requestCount >= maxRequests) {
            throw new RateLimitExceededException(errorMessage);  // Customizable error message
        }

        // Add current timestamp to the sorted set
        redisTemplate.opsForZSet().add(key, String.valueOf(currentTime), currentTime);

        // Set expiry for the key
        redisTemplate.expire(key, timeWindow, TimeUnit.MINUTES);

        // Proceed with the actual method execution
        return joinPoint.proceed();
    }

    private String getClientIp() {
        HttpServletRequest request = ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();

        // Retrieve IP address from headers or fallback to remote address
        String ipAddress = request.getHeader("X-Forwarded-For");

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        return ipAddress;
    }
}
