package dev.webstarter.system.audit;

import java.util.List;

import org.springframework.stereotype.Component;

/** Operation-audit REST boundaries owned by the system module. */
@Component
public final class SystemOperationAuditRouteContributor implements OperationAuditRouteContributor {

    private static final List<OperationAuditRoute> ROUTES = List.of(
            OperationAuditRoute.filterOwned("/api/users", "users", "user"),
            OperationAuditRoute.filterOwned("/api/roles", "roles", "role"),
            OperationAuditRoute.filterOwned("/api/permissions", "permissions", "permission"),
            OperationAuditRoute.filterOwned("/api/menus", "menus", "menu"),
            OperationAuditRoute.filterOwned("/api/configs", "configs", "config"));

    @Override
    public List<OperationAuditRoute> operationAuditRoutes() {
        return ROUTES;
    }
}
