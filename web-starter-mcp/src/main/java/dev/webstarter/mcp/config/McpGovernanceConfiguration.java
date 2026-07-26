package dev.webstarter.mcp.config;

import java.time.Clock;
import java.util.UUID;

import dev.webstarter.mcp.governance.McpRateLimiter;
import dev.webstarter.mcp.governance.McpSessionRegistry;
import dev.webstarter.mcp.governance.RedisMcpRateLimiter;
import dev.webstarter.mcp.governance.RedisMcpSessionRegistry;
import dev.webstarter.security.token.TokenHasher;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({McpSessionProperties.class, McpRateLimitProperties.class})
public class McpGovernanceConfiguration {

    @Bean
    McpSessionRegistry mcpSessionRegistry(
            StringRedisTemplate redis,
            TokenHasher tokenHasher,
            McpSessionProperties properties) {
        String nodeId = UUID.randomUUID().toString().replace("-", "");
        return new RedisMcpSessionRegistry(redis, tokenHasher, properties, Clock.systemUTC(), nodeId);
    }

    @Bean
    McpRateLimiter mcpRateLimiter(
            StringRedisTemplate redis,
            TokenHasher tokenHasher,
            McpRateLimitProperties properties) {
        return new RedisMcpRateLimiter(redis, tokenHasher, properties);
    }
}
