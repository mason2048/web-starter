package dev.webstarter.mcp.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import io.modelcontextprotocol.json.McpJsonMapper;

/** Shared lossless identifier contract for MCP schemas, arguments, and results. */
final class McpIdentifierContract {

    static final String POSITIVE_LONG_PATTERN = buildPositiveLongPattern();

    private static final Pattern CANONICAL_POSITIVE_DECIMAL = Pattern.compile("[1-9][0-9]*");

    private McpIdentifierContract() {
    }

    static Long optionalId(Object raw, String name) {
        if (raw == null) {
            return null;
        }
        if (!(raw instanceof String value) || !CANONICAL_POSITIVE_DECIMAL.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be a positive decimal string");
        }
        try {
            return Long.valueOf(value);
        }
        catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " is outside the identifier range", exception);
        }
    }

    static long requiredId(Object raw, String name) {
        Long value = optionalId(raw, name);
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    static Object normalizeOutput(McpJsonMapper jsonMapper, Object value) {
        Object genericValue = jsonMapper.convertValue(value, Object.class);
        return normalizeOutputValue(null, genericValue);
    }

    private static Object normalizeOutputValue(String propertyName, Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            map.forEach((key, item) -> {
                String name = String.valueOf(key);
                normalized.put(name, normalizeOutputValue(name, item));
            });
            return normalized;
        }
        if (value instanceof List<?> list) {
            if (isIdCollectionName(propertyName)) {
                return list.stream().map(McpIdentifierContract::decimalString).toList();
            }
            return list.stream().map(item -> normalizeOutputValue(null, item)).toList();
        }
        if (isScalarIdName(propertyName) && value instanceof Number) {
            return value.toString();
        }
        return value;
    }

    private static Object decimalString(Object value) {
        return value instanceof Number ? value.toString() : value;
    }

    private static boolean isScalarIdName(String name) {
        return name != null && ("id".equals(name) || name.endsWith("Id"));
    }

    private static boolean isIdCollectionName(String name) {
        return name != null && ("ids".equals(name) || name.endsWith("Ids"));
    }

    /**
     * Builds an anchored decimal-string regex for the inclusive range {@code 1..Long.MAX_VALUE}.
     * Keeping the bound in the schema prevents clients from accepting a value the Java parser
     * must later reject.
     */
    private static String buildPositiveLongPattern() {
        String maximum = Long.toString(Long.MAX_VALUE);
        List<String> alternatives = new ArrayList<>();
        alternatives.add("[1-9][0-9]{0," + (maximum.length() - 2) + "}");

        for (int index = 0; index < maximum.length(); index++) {
            int maximumDigit = maximum.charAt(index) - '0';
            int minimumDigit = index == 0 ? 1 : 0;
            if (maximumDigit <= minimumDigit) {
                continue;
            }
            String prefix = maximum.substring(0, index);
            String digit = digitRange(minimumDigit, maximumDigit - 1);
            int remainingDigits = maximum.length() - index - 1;
            String suffix = remainingDigits == 0 ? "" : "[0-9]{" + remainingDigits + "}";
            alternatives.add(prefix + digit + suffix);
        }
        alternatives.add(maximum);
        return "^(?:" + String.join("|", alternatives) + ")$";
    }

    private static String digitRange(int minimum, int maximum) {
        return minimum == maximum ? Integer.toString(minimum) : "[" + minimum + "-" + maximum + "]";
    }
}
