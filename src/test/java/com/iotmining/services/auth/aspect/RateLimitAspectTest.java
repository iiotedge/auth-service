package com.iotmining.services.auth.aspect;

import com.iotmining.services.auth.exceptions.RateLimitExceededException;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("RateLimitAspect")
class RateLimitAspectTest {

    private static final int MAX_REQUESTS = 5;

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ZSetOperations<String, String> zSetOperations;
    @Mock private ProceedingJoinPoint joinPoint;

    private RateLimitAspect aspect;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        aspect = new RateLimitAspect();
        ReflectionTestUtils.setField(aspect, "redisTemplate", redisTemplate);
        ReflectionTestUtils.setField(aspect, "maxRequests", MAX_REQUESTS);
        ReflectionTestUtils.setField(aspect, "timeWindow", 1L);
        ReflectionTestUtils.setField(aspect, "errorMessage", "Rate limit exceeded, please try again later");

        request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.10");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("proceeds and records the request while under the limit")
    void proceedsUnderLimit() throws Throwable {
        when(zSetOperations.count(anyString(), anyDouble(), anyDouble())).thenReturn((long) MAX_REQUESTS - 1);
        when(joinPoint.proceed()).thenReturn("controller-result");

        Object result = aspect.rateLimit(joinPoint);

        assertThat(result).isEqualTo("controller-result");
        verify(zSetOperations).add(eq("rate_limit:192.0.2.10"), anyString(), anyDouble());
        verify(redisTemplate).expire("rate_limit:192.0.2.10", 1L, TimeUnit.MINUTES);
    }

    @Test
    @DisplayName("evicts entries older than the sliding window before counting")
    void evictsExpiredWindowEntries() throws Throwable {
        when(zSetOperations.count(anyString(), anyDouble(), anyDouble())).thenReturn(0L);
        when(joinPoint.proceed()).thenReturn(null);

        aspect.rateLimit(joinPoint);

        verify(zSetOperations).removeRangeByScore(eq("rate_limit:192.0.2.10"), eq(0.0d), anyDouble());
    }

    @Test
    @DisplayName("rejects the request once the limit is reached and never invokes the method")
    void rejectsAtLimit() throws Throwable {
        when(zSetOperations.count(anyString(), anyDouble(), anyDouble())).thenReturn((long) MAX_REQUESTS);

        assertThatThrownBy(() -> aspect.rateLimit(joinPoint))
                .isInstanceOf(RateLimitExceededException.class)
                .hasMessageContaining("Rate limit exceeded");
        verify(joinPoint, never()).proceed();
        verify(zSetOperations, never()).add(anyString(), anyString(), anyDouble());
        verify(redisTemplate, never()).expire(anyString(), anyLong(), eq(TimeUnit.MINUTES));
    }

    @Test
    @DisplayName("rate-limits by the X-Forwarded-For client IP when behind a proxy")
    void usesForwardedForIp() throws Throwable {
        request.addHeader("X-Forwarded-For", "203.0.113.7");
        when(zSetOperations.count(anyString(), anyDouble(), anyDouble())).thenReturn(0L);
        when(joinPoint.proceed()).thenReturn(null);

        aspect.rateLimit(joinPoint);

        verify(zSetOperations).add(eq("rate_limit:203.0.113.7"), anyString(), anyDouble());
    }

    @Test
    @DisplayName("falls back to the remote address when proxy headers are absent")
    void fallsBackToRemoteAddress() throws Throwable {
        when(zSetOperations.count(anyString(), anyDouble(), anyDouble())).thenReturn(0L);
        when(joinPoint.proceed()).thenReturn(null);

        aspect.rateLimit(joinPoint);

        verify(zSetOperations).add(eq("rate_limit:192.0.2.10"), anyString(), anyDouble());
    }
}
