package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class McpGovernanceRuntimeSupportTest {

    private static final String COMMIT = "0123456789abcdef0123456789abcdef01234567";

    @Test
    void acceptsOnlyFormalReleaseIdentityExpectations() {
        var identity = McpGovernanceRuntimeSupport.expectedRuntimeIdentity("2.0.0", COMMIT);

        assertThat(identity.version()).isEqualTo("2.0.0");
        assertThat(identity.gitCommit()).isEqualTo(COMMIT);
        assertThat(McpGovernanceRuntimeSupport.expectedRuntimeIdentity("2.0.0-rc.1", "a".repeat(64)))
                .isEqualTo(new McpGovernanceRuntimeSupport.ExpectedRuntimeIdentity(
                        "2.0.0-rc.1", "a".repeat(64)));
    }

    @Test
    void rejectsSnapshotUppercaseShortAndNonCanonicalExpectations() {
        assertThatThrownBy(() -> McpGovernanceRuntimeSupport.expectedRuntimeIdentity(
                "2.0.0-SNAPSHOT", COMMIT)).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> McpGovernanceRuntimeSupport.expectedRuntimeIdentity(
                "2.0", COMMIT)).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> McpGovernanceRuntimeSupport.expectedRuntimeIdentity(
                "2.0.0", COMMIT.toUpperCase())).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> McpGovernanceRuntimeSupport.expectedRuntimeIdentity(
                "2.0.0", "a".repeat(39))).isInstanceOf(AssertionError.class);
    }
}
