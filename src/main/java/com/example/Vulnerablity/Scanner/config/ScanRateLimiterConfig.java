package com.example.Vulnerablity.Scanner.config;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.time.Duration;

@Configuration
public class ScanRateLimiterConfig {  // Class renamed here
    private static final String SCAN_RATE_LIMITER = "scanRateLimiter";

    @Bean
    public RateLimiter scanRateLimiter() {
        RateLimiterConfig config = RateLimiterConfig.custom()
                .limitRefreshPeriod(Duration.ofMinutes(1))
                .limitForPeriod(10) // 10 requests per minute
                .timeoutDuration(Duration.ofSeconds(5))
                .build();

        return RateLimiterRegistry.of(config).rateLimiter(SCAN_RATE_LIMITER);
    }
}