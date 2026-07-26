package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class McpInputValidatorTest {

    @Test
    void rejectsAnExplicitNullForAnOptionalStringProperty() {
        Map<String, Object> schema = Map.of(
                "type", "object",
                "properties", Map.of("description", Map.of("type", "string")),
                "required", List.of(),
                "additionalProperties", false);
        Map<String, Object> arguments = new LinkedHashMap<>();
        arguments.put("description", null);

        assertThatThrownBy(() -> McpInputValidator.validate(schema, arguments))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("description must not be null");
    }
}
