package dev.webstarter.mcp.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.webstarter.mcp.governance.McpToolRisk;
import io.modelcontextprotocol.json.McpJsonDefaults;
import org.junit.jupiter.api.Test;

import dev.webstarter.mcp.governance.McpToolRisk;
import dev.webstarter.mcp.service.McpToolCatalog;

class McpRequestDescriptorTest {

    @Test
    void resolvesGeneratedToolPermissionAndRiskFromTheRegisteredCatalog() throws Exception {
        McpToolCatalog catalog = mock(McpToolCatalog.class);
        when(catalog.permissionForRegisteredTool("asset.remove")).thenReturn("asset:remove");
        when(catalog.riskForRegisteredTool("asset.remove")).thenReturn(McpToolRisk.DESTRUCTIVE);

        McpRequestDescriptor descriptor = McpRequestDescriptor.describe(
                "POST",
                """
                        {"jsonrpc":"2.0","id":7,"method":"tools/call",
                         "params":{"name":"asset.remove","arguments":{"id":"1"}}}
                        """.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                McpJsonDefaults.getMapper(),
                catalog);

        assertThat(descriptor.toolName()).isEqualTo("asset.remove");
        assertThat(descriptor.permission()).isEqualTo("asset:remove");
        assertThat(descriptor.risk()).isEqualTo(McpToolRisk.DESTRUCTIVE);
    }

    @Test
    void classifiesToolRiskWithoutRetainingArguments() {
        String sensitive = "must-not-be-retained";
        McpRequestDescriptor descriptor = McpRequestDescriptor.describe(
                "POST",
                ("""
                        {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                          "name":"project.remove","arguments":{"secret":"%s"}
                        }}
                        """).formatted(sensitive).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                McpJsonDefaults.getMapper());

        assertThat(descriptor.toolName()).isEqualTo("project.remove");
        assertThat(descriptor.permission()).isEqualTo("project:remove");
        assertThat(descriptor.risk()).isEqualTo(McpToolRisk.DESTRUCTIVE);
        assertThat(descriptor.toString()).doesNotContain(sensitive);
    }

    @Test
    void treatsUnknownAndMalformedMessagesAsProtocolRisk() {
        assertThat(McpRequestDescriptor.describe(
                "POST", "not-json".getBytes(), McpJsonDefaults.getMapper()).risk())
                .isEqualTo(McpToolRisk.PROTOCOL);
        assertThat(McpRequestDescriptor.describe(
                "GET", null, McpJsonDefaults.getMapper()).auditOperation())
                .isEqualTo("session.stream");
    }
}
