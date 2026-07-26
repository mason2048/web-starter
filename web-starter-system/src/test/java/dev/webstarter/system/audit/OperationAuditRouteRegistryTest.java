package dev.webstarter.system.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

class OperationAuditRouteRegistryTest {

    @Test
    void matchesOnSegmentBoundariesAndPrefersTheLongestContribution() {
        OperationAuditRoute root = OperationAuditRoute.filterOwned(
                "/api/security", "security", "security");
        OperationAuditRoute nested = OperationAuditRoute.filterOwned(
                "/api/security/oauth-clients", "security", "oauth-client");
        OperationAuditRouteRegistry registry = new OperationAuditRouteRegistry(List.of(
                () -> List.of(root, nested)));

        assertThat(registry.match("/api/security/oauth-clients/agent-1"))
                .contains(nested);
        assertThat(registry.match("/api/security/me"))
                .contains(root);
        assertThat(registry.match("/api/security-extra"))
                .isEmpty();
    }

    @Test
    void duplicatePrefixesFailFastInsteadOfChoosingAnAmbiguousOwner() {
        OperationAuditRoute first = OperationAuditRoute.serviceOwned(
                "/api/widgets", "widget", "widget");
        OperationAuditRoute second = OperationAuditRoute.filterOwned(
                "/api/widgets", "other", "other");

        assertThatThrownBy(() -> new OperationAuditRouteRegistry(List.of(
                () -> List.of(first),
                () -> List.of(second))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("duplicate operation audit path prefix");
    }

    @Test
    void routeValuesRejectUnsafeOrAmbiguousNames() {
        assertThatThrownBy(() -> OperationAuditRoute.serviceOwned(
                "/api/widgets/../users", "widget", "widget"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperationAuditRoute.serviceOwned(
                "/api/widgets", "Widget", "widget"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperationAuditRoute.serviceOwned(
                "/api/widgets/-archive", "widget", "widget"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperationAuditRoute.serviceOwned(
                "/api/widgets", "widget-", "widget"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void namedFactoriesMakeTheSuccessAuditOwnerExplicit() {
        OperationAuditRoute serviceOwned = OperationAuditRoute.serviceOwned(
                "/api/x", "example", "example");
        OperationAuditRoute filterOwned = OperationAuditRoute.filterOwned(
                "/api/y", "example", "example");

        assertThat(serviceOwned.successAuditedByService()).isTrue();
        assertThat(filterOwned.successAuditedByService()).isFalse();
    }
}
