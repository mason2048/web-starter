package dev.webstarter.mcp.service;

import java.util.Map;

public final class McpArguments {

    private final Map<String, Object> values;

    public McpArguments(Map<String, Object> values) {
        this.values = values == null ? Map.of() : values;
    }

    public String requiredString(String name) {
        String value = optionalString(name);
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    public String optionalString(String name) {
        Object raw = values.get(name);
        if (raw == null) {
            return null;
        }
        if (!(raw instanceof String value)) {
            throw new IllegalArgumentException(name + " must be a string");
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public long longValue(String name, long defaultValue) {
        Long value = optionalLong(name);
        return value == null ? defaultValue : value;
    }

    public long requiredLong(String name) {
        Long value = optionalLong(name);
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    public Long optionalLong(String name) {
        Object raw = values.get(name);
        if (raw == null) {
            return null;
        }
        if (!(raw instanceof Number number)) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
        double decimal = number.doubleValue();
        long integer = number.longValue();
        if (!Double.isFinite(decimal) || decimal != integer) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
        return integer;
    }

    public long requiredId(String name) {
        Long value = optionalId(name);
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    public Long optionalId(String name) {
        return McpIdentifierContract.optionalId(values.get(name), name);
    }

    public int requiredInteger(String name) {
        long value = requiredLong(name);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(name + " is outside the integer range");
        }
        return (int) value;
    }
}
