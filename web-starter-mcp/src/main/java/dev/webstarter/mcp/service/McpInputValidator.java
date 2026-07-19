package dev.webstarter.mcp.service;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

final class McpInputValidator {

    private McpInputValidator() {
    }

    static Map<String, Object> validate(Map<String, Object> schema, Map<String, Object> arguments) {
        Map<String, Object> values = arguments == null ? Map.of() : arguments;
        Map<String, Object> properties = map(schema.get("properties"));
        Set<String> unexpected = new LinkedHashSet<>(values.keySet());
        unexpected.removeAll(properties.keySet());
        if (!unexpected.isEmpty()) {
            throw new IllegalArgumentException("Unexpected tool argument: " + unexpected.iterator().next());
        }
        Object requiredValue = schema.get("required");
        if (requiredValue instanceof Collection<?> required) {
            for (Object item : required) {
                String name = String.valueOf(item);
                if (!values.containsKey(name) || values.get(name) == null) {
                    throw new IllegalArgumentException(name + " is required");
                }
            }
        }
        values.forEach((name, value) -> validateValue(name, value, map(properties.get(name))));
        return values;
    }

    private static void validateValue(String name, Object value, Map<String, Object> definition) {
        if (value == null) {
            return;
        }
        String type = String.valueOf(definition.get("type"));
        if ("string".equals(type)) {
            if (!(value instanceof String text)) {
                throw new IllegalArgumentException(name + " must be a string");
            }
            Number minimumLength = number(definition.get("minLength"));
            Number maximumLength = number(definition.get("maxLength"));
            if (minimumLength != null && text.codePointCount(0, text.length()) < minimumLength.intValue()) {
                throw new IllegalArgumentException(name + " must not be blank");
            }
            if (maximumLength != null && text.codePointCount(0, text.length()) > maximumLength.intValue()) {
                throw new IllegalArgumentException(name + " is too long");
            }
            Object pattern = definition.get("pattern");
            if (pattern instanceof String expression && !text.matches(expression)) {
                throw new IllegalArgumentException(name + " has an invalid format");
            }
            Object enumValues = definition.get("enum");
            if (enumValues instanceof Collection<?> allowed && !allowed.contains(text)) {
                throw new IllegalArgumentException(name + " has an unsupported value");
            }
            return;
        }
        if ("integer".equals(type)) {
            if (!(value instanceof Number number)) {
                throw new IllegalArgumentException(name + " must be an integer");
            }
            double decimal = number.doubleValue();
            long integer = number.longValue();
            if (!Double.isFinite(decimal) || decimal != integer) {
                throw new IllegalArgumentException(name + " must be an integer");
            }
            Number minimum = number(definition.get("minimum"));
            Number maximum = number(definition.get("maximum"));
            if (minimum != null && integer < minimum.longValue()) {
                throw new IllegalArgumentException(name + " is below the minimum");
            }
            if (maximum != null && integer > maximum.longValue()) {
                throw new IllegalArgumentException(name + " is above the maximum");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    private static Number number(Object value) {
        return value instanceof Number number ? number : null;
    }
}
