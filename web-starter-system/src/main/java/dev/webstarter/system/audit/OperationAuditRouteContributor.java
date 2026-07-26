package dev.webstarter.system.audit;

import java.util.Collection;

/** Implemented by a module that exposes state-changing REST resources. */
@FunctionalInterface
public interface OperationAuditRouteContributor {

    Collection<OperationAuditRoute> operationAuditRoutes();
}
