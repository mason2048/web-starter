package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class McpRuntimeIdentityTest {

    private static final String COMMIT = "0123456789abcdef0123456789abcdef01234567";

    @Test
    void exposesTheSameVersionAndRevisionInInitializeAndSystemInfo() {
        McpRuntimeIdentity identity = new McpRuntimeIdentity("2.0.0", COMMIT);

        assertThat(identity.serverInfo().name()).isEqualTo("web-starter-mcp");
        assertThat(identity.serverInfo().version()).isEqualTo("2.0.0");
        assertThat(identity.serverInfo().description())
                .isEqualTo("gitRevision=" + COMMIT);
        assertThat(identity.systemInfo())
                .containsEntry("server", "web-starter-mcp")
                .containsEntry("version", "2.0.0")
                .containsEntry("gitRevision", COMMIT)
                .containsEntry("java", Runtime.version().feature())
                .containsKeys("product", "time");
    }

    @Test
    void acceptsOnlyAnExplicitLocalMarkerOrCanonicalLowercaseGitObjectId() {
        assertThat(new McpRuntimeIdentity("2.0.0-SNAPSHOT", "local").gitRevision())
                .isEqualTo("local");
        assertThat(new McpRuntimeIdentity("2.0.0", "a".repeat(64)).gitRevision())
                .isEqualTo("a".repeat(64));

        for (String malformed : new String[] {"", " local", "ABCDEF", "a".repeat(39), "a".repeat(65)}) {
            assertThatThrownBy(() -> new McpRuntimeIdentity("2.0.0", malformed))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("git revision");
        }
    }
}
