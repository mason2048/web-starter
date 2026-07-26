package dev.webstarter.mcp.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@MapperScan("dev.webstarter.mcp.persistence.mapper")
public class McpPersistenceConfiguration {
}
