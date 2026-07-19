package dev.webstarter.core.security;

import java.io.Serializable;
import java.util.Set;

public record CurrentCaller(
        CallerType callerType,
        String subjectId,
        String username,
        String displayName,
        String tokenId,
        String clientId,
        Set<String> scopes,
        Set<String> permissions,
        Set<Long> menuIds,
        String traceId
) implements Serializable {

    private static final long serialVersionUID = 1L;
    public CurrentCaller {
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        menuIds = menuIds == null ? Set.of() : Set.copyOf(menuIds);
    }
}
