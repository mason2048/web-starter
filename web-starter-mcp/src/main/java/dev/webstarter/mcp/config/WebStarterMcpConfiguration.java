package dev.webstarter.mcp.config;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.server.transport.DefaultServerTransportSecurityValidator;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityValidator;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;

import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

import dev.webstarter.mcp.service.McpContentCatalog;
import dev.webstarter.mcp.service.McpRuntimeIdentity;
import dev.webstarter.mcp.service.McpToolCatalog;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({WebStarterMcpProperties.class, McpIdempotencyProperties.class})
public class WebStarterMcpConfiguration {

    public static final String MCP_ENDPOINT = "/mcp";

    @Bean
    McpJsonMapper mcpJsonMapper() {
        return McpJsonDefaults.getMapper();
    }

    @Bean
    McpRuntimeIdentity mcpRuntimeIdentity(
            @Value("${spring.application.version}") String applicationVersion,
            @Value("${web-starter.runtime.git-commit:local}") String gitRevision) {
        return new McpRuntimeIdentity(applicationVersion, gitRevision);
    }

    @Bean
    ServerTransportSecurityValidator mcpTransportSecurityValidator(WebStarterMcpProperties properties) {
        return DefaultServerTransportSecurityValidator.builder()
                .allowedHosts(properties.allowedHosts())
                .allowedOrigins(properties.allowedOrigins())
                .build();
    }

    @Bean
    HttpServletStreamableServerTransportProvider mcpTransportProvider(
            McpJsonMapper jsonMapper,
            ServerTransportSecurityValidator securityValidator) {
        return HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(jsonMapper)
                .mcpEndpoint(MCP_ENDPOINT)
                .securityValidator(securityValidator)
                .build();
    }

    @Bean
    ServletRegistrationBean<HttpServletStreamableServerTransportProvider> mcpServletRegistration(
            HttpServletStreamableServerTransportProvider provider) {
        ServletRegistrationBean<HttpServletStreamableServerTransportProvider> registration =
                new ServletRegistrationBean<>(provider, MCP_ENDPOINT);
        registration.setName("webStarterMcpStreamableHttp");
        registration.setLoadOnStartup(1);
        return registration;
    }

    @Bean(destroyMethod = "closeGracefully")
    McpSyncServer mcpSyncServer(
            HttpServletStreamableServerTransportProvider provider,
            McpJsonMapper jsonMapper,
            McpToolCatalog toolCatalog,
            McpContentCatalog contentCatalog,
            McpRuntimeIdentity runtimeIdentity) {
        return McpServer.sync(provider)
                .serverInfo(runtimeIdentity.serverInfo())
                .instructions("Internal management server. All operations enforce live RBAC and token scopes.")
                .jsonMapper(jsonMapper)
                .capabilities(ServerCapabilities.builder()
                        .tools(false)
                        .resources(false, false)
                        .prompts(false)
                        .build())
                .tools(toolCatalog.specifications())
                .resources(contentCatalog.resources())
                .prompts(contentCatalog.prompts())
                .strictToolNameValidation(true)
                // Validation is intentionally performed inside McpInvocationService so
                // malformed calls receive the same FAILED audit as business failures.
                .validateToolInputs(false)
                .immediateExecution(true)
                .build();
    }
}
