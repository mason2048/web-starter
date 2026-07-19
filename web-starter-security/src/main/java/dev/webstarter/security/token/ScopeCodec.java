package dev.webstarter.security.token;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class ScopeCodec {

    private ScopeCodec() {
    }

    public static String encode(Collection<String> values) {
        if (values == null) {
            return "";
        }
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .sorted()
                .collect(Collectors.joining(" "));
    }

    public static Set<String> decode(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.trim().split("\\s+"))
                .filter(item -> !item.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static String encodeLongs(Collection<Long> values) {
        if (values == null) {
            return "";
        }
        return values.stream().distinct().sorted().map(String::valueOf).collect(Collectors.joining(","));
    }

    public static List<Long> decodeLongs(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .map(Long::valueOf)
                .toList();
    }

    public static List<String> decodeLines(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split("\\R"))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .toList();
    }

    public static String encodeLines(Collection<String> values) {
        if (values == null) {
            return "";
        }
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .distinct()
                .sorted()
                .collect(Collectors.joining("\n"));
    }
}
