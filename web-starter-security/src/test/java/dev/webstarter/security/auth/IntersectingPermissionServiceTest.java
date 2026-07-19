package dev.webstarter.security.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import org.junit.jupiter.api.Test;

import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;

class IntersectingPermissionServiceTest {

    private final IntersectingPermissionService permissions = new IntersectingPermissionService();

    @Test
    void tokenCallerNeedsBothLiveRbacAndScope() {
        assertThat(permissions.hasPermission(caller("token-1", Set.of("project:list"), Set.of("project:list")),
                "project:list")).isTrue();
        assertThat(permissions.hasPermission(caller("token-1", Set.of("project:list"), Set.of()),
                "project:list")).isFalse();
        assertThat(permissions.hasPermission(caller("token-1", Set.of(), Set.of("project:list")),
                "project:list")).isFalse();
    }

    @Test
    void webSessionUsesLiveRbacWithoutTokenScope() {
        assertThat(permissions.hasPermission(caller(null, Set.of(), Set.of("project:list")),
                "project:list")).isTrue();
    }

    @Test
    void tokenScopeWildcardIsNeverAcceptedButRbacWildcardStillNeedsExactScope() {
        assertThat(permissions.hasPermission(caller("token-1", Set.of("*"), Set.of("project:create")),
                "project:create")).isFalse();
        assertThat(permissions.hasPermission(caller("token-1", Set.of("project:create"), Set.of("*")),
                "project:create")).isTrue();
        assertThat(permissions.hasPermission(caller("token-1", Set.of("*"), Set.of()),
                "project:create")).isFalse();
    }

    private static CurrentCaller caller(String tokenId, Set<String> scopes, Set<String> permissions) {
        return new CurrentCaller(
                CallerType.USER,
                "1",
                "operator",
                "Operator",
                tokenId,
                null,
                scopes,
                permissions,
                Set.of(),
                "trace-1");
    }
}
