package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class McpRuntimeToolExpectationsTest {

    @Test
    void defaultsToTheSevenStableTools() {
        assertThat(McpRuntimeToolExpectations.parse(null)).containsExactlyInAnyOrder(
                "system.info", "project.list", "project.get", "project.create",
                "project.update", "project.remove", "audit.list");
    }

    @Test
    void addsOnlyTheExactValidatedGeneratedToolGrammar() {
        assertThat(McpRuntimeToolExpectations.parse(
                "asset.list,asset.get,asset.create,asset.update,asset.remove"))
                .contains("asset.list", "asset.get", "asset.create", "asset.update", "asset.remove")
                .hasSize(12);

        assertThatThrownBy(() -> McpRuntimeToolExpectations.parse("asset.list,asset.list"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("repeats");
        assertThatThrownBy(() -> McpRuntimeToolExpectations.parse("asset.shell"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid");
    }
}
