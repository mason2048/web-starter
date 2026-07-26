package dev.webstarter.admin.web;

import static org.assertj.core.api.Assertions.assertThat;

import dev.webstarter.project.audit.ProjectOperationAuditRouteContributor;
import dev.webstarter.security.audit.SecurityOperationAuditRouteContributor;
import dev.webstarter.system.audit.OperationAuditRouteRegistry;
import dev.webstarter.system.audit.SystemOperationAuditRouteContributor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

class OperationAuditRouteRegistryContextTest {

    @Test
    void aggregatesTheRouteContributionsFromIndependentModules() {
        new ApplicationContextRunner()
                .withUserConfiguration(TestConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(OperationAuditRouteRegistry.class);

                    OperationAuditRouteRegistry registry =
                            context.getBean(OperationAuditRouteRegistry.class);
                    assertThat(registry.routes()).hasSize(10);
                    assertThat(registry.match("/api/users/7")).isPresent();
                    assertThat(registry.match("/api/security/oauth-clients/agent-1"))
                            .isPresent();
                    assertThat(registry.match("/api/projects/7"))
                            .get()
                            .extracting(route -> route.successAuditedByService())
                            .isEqualTo(true);
                    assertThat(registry.match("/api/projects-archive")).isEmpty();
                });
    }

    @Configuration(proxyBeanMethods = false)
    @Import({
            OperationAuditRouteRegistry.class,
            SystemOperationAuditRouteContributor.class,
            SecurityOperationAuditRouteContributor.class,
            ProjectOperationAuditRouteContributor.class
    })
    static class TestConfiguration {
    }
}
