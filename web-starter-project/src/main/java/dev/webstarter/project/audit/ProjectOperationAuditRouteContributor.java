package dev.webstarter.project.audit;

import java.util.List;

import dev.webstarter.system.audit.OperationAuditRoute;
import dev.webstarter.system.audit.OperationAuditRouteContributor;
import org.springframework.stereotype.Component;

/** Project REST failures are filter-audited; successful writes are audited by the shared Service. */
@Component
public final class ProjectOperationAuditRouteContributor implements OperationAuditRouteContributor {

    private static final List<OperationAuditRoute> ROUTES = List.of(
            OperationAuditRoute.serviceOwned("/api/projects", "project", "project"));

    @Override
    public List<OperationAuditRoute> operationAuditRoutes() {
        return ROUTES;
    }
}
