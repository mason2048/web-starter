package dev.webstarter.system.audit;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.springframework.stereotype.Component;

/** Aggregates module-owned audit routes and performs segment-safe longest-prefix matching. */
@Component
public final class OperationAuditRouteRegistry {

    private final List<OperationAuditRoute> routes;

    public OperationAuditRouteRegistry(List<OperationAuditRouteContributor> contributors) {
        Objects.requireNonNull(contributors, "contributors");
        Map<String, OperationAuditRoute> unique = new LinkedHashMap<>();
        for (OperationAuditRouteContributor contributor : List.copyOf(contributors)) {
            Collection<OperationAuditRoute> contributed = Objects.requireNonNull(
                    contributor.operationAuditRoutes(), "operation audit routes");
            for (OperationAuditRoute route : List.copyOf(contributed)) {
                Objects.requireNonNull(route, "operation audit route");
                if (unique.putIfAbsent(route.pathPrefix(), route) != null) {
                    throw new IllegalStateException(
                            "duplicate operation audit path prefix: " + route.pathPrefix());
                }
            }
        }
        List<OperationAuditRoute> ordered = new ArrayList<>(unique.values());
        ordered.sort(Comparator
                .comparingInt((OperationAuditRoute route) -> route.pathPrefix().length())
                .reversed()
                .thenComparing(OperationAuditRoute::pathPrefix));
        this.routes = List.copyOf(ordered);
    }

    public Optional<OperationAuditRoute> match(String requestPath) {
        return routes.stream().filter(route -> route.matches(requestPath)).findFirst();
    }

    public List<OperationAuditRoute> routes() {
        return routes;
    }
}
