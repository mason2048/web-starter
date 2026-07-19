package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;

class McpArgumentsTest {

    @Test
    void parsesUnsafeJavaScriptAndMaximumLongIdentifiersWithoutPrecisionLoss() {
        McpArguments arguments = new McpArguments(Map.of("id", "9007199254740993"));
        McpArguments maximum = new McpArguments(Map.of("id", Long.toString(Long.MAX_VALUE)));

        assertThat(arguments.requiredId("id")).isEqualTo(9_007_199_254_740_993L);
        assertThat(maximum.requiredId("id")).isEqualTo(Long.MAX_VALUE);
    }

    @Test
    void rejectsNumericNonCanonicalAndOutOfRangeIdentifiers() {
        assertInvalidId(9_007_199_254_740_993L);
        assertInvalidId("0");
        assertInvalidId("01");
        assertInvalidId("-1");
        assertInvalidId("1.0");
        assertInvalidId(" 1");
        assertInvalidId("9223372036854775808");
    }

    private static void assertInvalidId(Object value) {
        McpArguments arguments = new McpArguments(Map.of("id", value));
        assertThatThrownBy(() -> arguments.requiredId("id"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
