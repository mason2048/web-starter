package dev.webstarter.security.audit;

import java.util.List;

import dev.webstarter.system.audit.OperationAuditRoute;
import dev.webstarter.system.audit.OperationAuditRouteContributor;
import org.springframework.stereotype.Component;

/** Operation-audit REST boundaries owned by the security module. */
@Component
public final class SecurityOperationAuditRouteContributor implements OperationAuditRouteContributor {

    private static final List<OperationAuditRoute> ROUTES = List.of(
            OperationAuditRoute.filterOwned(
                    "/api/security/oauth-clients", "security", "oauth-client"),
            OperationAuditRoute.filterOwned(
                    "/api/security/personal-tokens", "security", "token"),
            OperationAuditRoute.filterOwned(
                    "/api/security/service-accounts", "security", "service-account"),
            OperationAuditRoute.filterOwned(
                    "/api/security/me", "security", "me"));

    @Override
    public List<OperationAuditRoute> operationAuditRoutes() {
        return ROUTES;
    }
}
