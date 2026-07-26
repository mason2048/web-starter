package dev.webstarter.tooling;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class CliOptions {

    private final Map<String, String> values;
    private final Set<String> flags;

    private CliOptions(Map<String, String> values, Set<String> flags) {
        this.values = Map.copyOf(values);
        this.flags = Set.copyOf(flags);
    }

    public static CliOptions parse(String[] arguments, int start, Set<String> valueNames, Set<String> flagNames) {
        Map<String, String> values = new LinkedHashMap<>();
        Set<String> flags = new LinkedHashSet<>();
        for (int index = start; index < arguments.length; index++) {
            String argument = arguments[index];
            if (!argument.startsWith("--") || argument.length() == 2) {
                throw Checks.usage("unexpected argument: " + argument);
            }
            String name = argument.substring(2);
            if (flagNames.contains(name)) {
                if (!flags.add(name)) {
                    throw Checks.usage("duplicate option: --" + name);
                }
                continue;
            }
            if (!valueNames.contains(name)) {
                throw Checks.usage("unknown option: --" + name);
            }
            if (values.containsKey(name)) {
                throw Checks.usage("duplicate option: --" + name);
            }
            if (++index >= arguments.length || arguments[index].startsWith("--")) {
                throw Checks.usage("missing value for --" + name);
            }
            values.put(name, arguments[index]);
        }
        return new CliOptions(values, flags);
    }

    public String required(String name) {
        String value = values.get(name);
        if (value == null || value.isBlank()) {
            throw Checks.usage("--" + name + " is required");
        }
        return value;
    }

    public String optional(String name, String fallback) {
        return values.getOrDefault(name, fallback);
    }

    public boolean flag(String name) {
        return flags.contains(name);
    }
}
