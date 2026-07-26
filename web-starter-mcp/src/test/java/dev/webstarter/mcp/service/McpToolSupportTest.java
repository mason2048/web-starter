package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import dev.webstarter.mcp.governance.McpToolRisk;
import io.modelcontextprotocol.json.McpJsonDefaults;
import org.junit.jupiter.api.Test;

class McpToolSupportTest {

    @Test
    void contractInspectionBuildsMetadataWithoutRuntimeServicesButCannotExecute() {
        McpToolSupport support = McpToolSupport.forContractInspection(
                McpJsonDefaults.getMapper());

        McpToolContribution contribution = support.specification(
                "asset.list",
                "List assets",
                McpToolSupport.objectSchema(Map.of(), List.of()),
                McpToolSupport.objectSchema(Map.of("records", Map.of("type", "array")),
                        List.of("records")),
                McpToolSupport.readOnly(),
                "asset:list",
                McpToolRisk.READ,
                arguments -> Map.of("records", List.of()));

        assertThat(contribution.name()).isEqualTo("asset.list");
        assertThat(contribution.permission()).isEqualTo("asset:list");
        assertThat(contribution.specification().tool().outputSchema()).containsKey("oneOf");
        assertThatThrownBy(() -> support.idempotent(
                "asset.create",
                Map.of(McpToolSupport.IDEMPOTENCY_KEY, "asset-create-0001"),
                () -> Map.of("id", "1")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot execute handlers");
    }
}
