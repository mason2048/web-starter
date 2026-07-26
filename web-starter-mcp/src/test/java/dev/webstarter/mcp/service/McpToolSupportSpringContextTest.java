package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.json.McpJsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

class McpToolSupportSpringContextTest {

    @Test
    void selectsExecutableConstructorWhenInspectionFactoryAddsAnotherConstructor() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfiguration.class)
                .withBean(McpInvocationService.class,
                        () -> mock(McpInvocationService.class))
                .withBean(McpIdempotencyService.class,
                        () -> mock(McpIdempotencyService.class))
                .withBean(McpJsonMapper.class, McpJsonDefaults::getMapper)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(McpToolSupport.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @Import(McpToolSupport.class)
    static class TestConfiguration {
    }
}
