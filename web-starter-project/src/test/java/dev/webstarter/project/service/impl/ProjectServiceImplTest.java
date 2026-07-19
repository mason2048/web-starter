package dev.webstarter.project.service.impl;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.project.domain.Project;
import dev.webstarter.project.dto.ProjectCreateRequest;
import dev.webstarter.project.dto.ProjectResponse;
import dev.webstarter.project.persistence.mapper.ProjectMapper;
import dev.webstarter.system.audit.AuditLogRecorder;
import dev.webstarter.system.audit.LoginAuditEvent;
import dev.webstarter.system.audit.McpCallAuditEvent;
import dev.webstarter.system.audit.OperationAuditEvent;
import dev.webstarter.system.service.RbacSnapshot;
import dev.webstarter.system.service.SystemIdentity;
import dev.webstarter.system.service.SystemIdentityService;
import dev.webstarter.system.service.SystemUserSummary;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProjectServiceImplTest {

    @Test
    void createNormalizesCodeAndResolvesOwnerName() {
        CurrentCaller caller = new CurrentCaller(CallerType.USER, "1", "admin", "Administrator", null, null,
                Set.of(), Set.of("project:create"), Set.of(2002L), "trace-test");
        CallerContext callerContext = () -> Optional.of(caller);
        PermissionService permissionService = (current, permission) -> current.permissions().contains(permission);
        SystemIdentityService identityService = identityServiceStub();
        ProjectMapper projectMapper = projectMapperStub();
        ProjectServiceImpl service = new ProjectServiceImpl(
                callerContext, permissionService, projectMapper, identityService, noOpAuditRecorder());

        ProjectResponse response = service.create(new ProjectCreateRequest("Starter", "demo_one", 2L, "PLANNING", "Example"));

        assertEquals(10L, response.id());
        assertEquals("DEMO_ONE", response.code());
        assertEquals("Project Owner", response.ownerName());
        assertEquals(0, response.version());
    }

    private ProjectMapper projectMapperStub() {
        return (ProjectMapper) Proxy.newProxyInstance(
                ProjectMapper.class.getClassLoader(),
                new Class<?>[]{ProjectMapper.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("selectCount")) {
                        return 0L;
                    }
                    if (method.getName().equals("insert")) {
                        Project project = (Project) args[0];
                        project.setId(10L);
                        return 1;
                    }
                    if (method.getReturnType().equals(int.class)) {
                        return 0;
                    }
                    if (method.getReturnType().equals(long.class)) {
                        return 0L;
                    }
                    if (method.getReturnType().equals(boolean.class)) {
                        return false;
                    }
                    return null;
                }
        );
    }

    private SystemIdentityService identityServiceStub() {
        return new SystemIdentityService() {
            @Override
            public Optional<SystemIdentity> loadByUsername(String username) {
                return Optional.empty();
            }

            @Override
            public Optional<SystemIdentity> loadById(Long userId) {
                return userId.equals(2L)
                        ? Optional.of(new SystemIdentity(
                                2L, "owner", "Project Owner", "hash", "ENABLED",
                                Set.of(), Set.of(), Set.of()))
                        : Optional.empty();
            }

            @Override
            public List<SystemUserSummary> listEnabledUsers() {
                return List.of(new SystemUserSummary(2L, "owner", "Project Owner"));
            }

            @Override
            public RbacSnapshot resolveRbacByRoleIds(Collection<Long> roleIds) {
                return RbacSnapshot.empty();
            }
        };
    }

    private AuditLogRecorder noOpAuditRecorder() {
        return new AuditLogRecorder() {
            @Override public void recordLogin(LoginAuditEvent event) { }
            @Override public void recordOperation(OperationAuditEvent event) { }
            @Override public void recordMcpCall(McpCallAuditEvent event) { }
        };
    }
}
