package dev.webstarter.tooling;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class Checks {

    private static final Pattern SLUG = Pattern.compile("[a-z][a-z0-9-]{1,48}[a-z0-9]");
    private static final Pattern MODULE = Pattern.compile("[a-z][a-z0-9]{1,30}");
    private static final Pattern LOWER_JAVA_SEGMENT = Pattern.compile("[a-z][a-z0-9_]*");
    private static final Pattern DATABASE = Pattern.compile("[a-z][a-z0-9_]{1,62}");
    private static final Pattern ENV_PREFIX = Pattern.compile("[A-Z][A-Z0-9_]{1,62}_");
    private static final Pattern TABLE = Pattern.compile("[a-z][a-z0-9_]{1,52}");
    private static final Pattern ROUTE = Pattern.compile("/[a-z][a-z0-9-/]{0,126}[a-z0-9]");
    private static final Pattern MIGRATION = Pattern.compile("[1-9][0-9]{0,17}");
    private static final Set<String> JAVA_KEYWORDS = Set.of(
            "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
            "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
            "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
            "interface", "long", "native", "new", "package", "private", "protected", "public",
            "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
            "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false", "null");
    private static final Set<String> JAVA_RESTRICTED_IDENTIFIERS = Set.of(
            "exports", "module", "open", "opens", "permits", "provides", "record", "requires",
            "sealed", "to", "transitive", "uses", "var", "when", "with", "yield");

    private Checks() {
    }

    public static String slug(String value, String name) {
        String normalized = required(value, name);
        if (!SLUG.matcher(normalized).matches()) {
            throw usage(name + " must be lower-kebab-case and 3-50 characters");
        }
        return normalized;
    }

    public static String moduleName(String value) {
        String normalized = required(value, "module name");
        if (!MODULE.matcher(normalized).matches()
                || JAVA_KEYWORDS.contains(normalized)
                || JAVA_RESTRICTED_IDENTIFIERS.contains(normalized)) {
            throw usage("module name must be lower-case alphanumeric and 2-31 characters");
        }
        return normalized;
    }

    public static String database(String value) {
        String normalized = required(value, "database");
        if (!DATABASE.matcher(normalized).matches()) {
            throw usage("database must be lower_snake_case and 3-63 characters");
        }
        return normalized;
    }

    public static String environmentPrefix(String value) {
        String normalized = required(value, "environment prefix");
        if (!ENV_PREFIX.matcher(normalized).matches()) {
            throw usage("environment prefix must be uppercase snake case and end with '_'");
        }
        return normalized;
    }

    public static String javaPackage(String value, String name) {
        String normalized = required(value, name);
        String[] parts = normalized.split("\\.", -1);
        if (parts.length < 2) {
            throw usage(name + " must contain at least two Java identifier segments");
        }
        for (String part : parts) {
            if (!LOWER_JAVA_SEGMENT.matcher(part).matches()
                    || JAVA_KEYWORDS.contains(part)
                    || JAVA_RESTRICTED_IDENTIFIERS.contains(part)) {
                throw usage(name + " must contain only lower-case ASCII Java package segments");
            }
        }
        return normalized;
    }

    public static String productName(String value) {
        String normalized = Normalizer.normalize(required(value, "product name"), Normalizer.Form.NFC);
        if (normalized.codePointCount(0, normalized.length()) > 80
                || normalized.codePoints().noneMatch(Character::isLetterOrDigit)
                || normalized.codePoints().anyMatch(codePoint -> !productNameCharacter(codePoint))) {
            throw usage("product name must include a letter or digit and use only 1-80 safe display characters");
        }
        return normalized;
    }

    public static String label(String value) {
        String normalized = Normalizer.normalize(required(value, "module label"), Normalizer.Form.NFC);
        if (normalized.codePointCount(0, normalized.length()) > 40
                || normalized.codePoints().anyMatch(codePoint -> !labelCharacter(codePoint))) {
            throw usage("module label must be 1-40 letters, digits, spaces, '_', '-', parentheses, or middle dots");
        }
        return normalized;
    }

    public static String table(String value) {
        String normalized = required(value, "table");
        if (!TABLE.matcher(normalized).matches()) {
            throw usage("table must be lower_snake_case and 2-53 characters");
        }
        return normalized;
    }

    public static String route(String value) {
        String normalized = required(value, "route");
        if (!ROUTE.matcher(normalized).matches() || normalized.contains("//") || normalized.contains("..")) {
            throw usage("route must be a normalized lower-case absolute path");
        }
        return normalized;
    }

    public static String migrationVersion(String value) {
        String normalized = required(value, "migration version");
        if (!MIGRATION.matcher(normalized).matches()) {
            throw usage("migration version must contain 1-18 decimal digits and cannot start with zero");
        }
        return normalized;
    }

    public static long positiveLong(String value, String name) {
        try {
            long result = Long.parseLong(required(value, name));
            if (result <= 0) {
                throw usage(name + " must be a positive integer");
            }
            return result;
        }
        catch (NumberFormatException exception) {
            throw usage(name + " must be a positive integer");
        }
    }

    public static Path existingDirectory(Path value, String name) {
        Path normalized = value.toAbsolutePath().normalize();
        if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(normalized)) {
            throw new ToolingException(ToolingException.PREREQUISITE, name + " must be an existing non-symlink directory");
        }
        return normalized;
    }

    public static Path safeRelative(Path value) {
        Path normalized = value.normalize();
        if (normalized.isAbsolute() || normalized.toString().isEmpty()
                || normalized.getNameCount() == 0 || normalized.startsWith("..")) {
            throw usage("unsafe relative path: " + value);
        }
        return normalized;
    }

    public static BigInteger migrationNumber(String value) {
        return new BigInteger(migrationVersion(value));
    }

    public static String pascalCase(String value) {
        StringBuilder result = new StringBuilder();
        for (String part : value.split("[-_]")) {
            if (part.isEmpty()) {
                continue;
            }
            result.append(part.substring(0, 1).toUpperCase(Locale.ROOT));
            if (part.length() > 1) {
                result.append(part.substring(1));
            }
        }
        if (result.isEmpty() || !Character.isJavaIdentifierStart(result.charAt(0))) {
            throw usage("value cannot be converted to a Java class name");
        }
        return result.toString();
    }

    public static ToolingException usage(String message) {
        return new ToolingException(ToolingException.USAGE, message);
    }

    public static ToolingException conflict(String message) {
        return new ToolingException(ToolingException.CONFLICT, message);
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) {
            throw usage(name + " is required");
        }
        return value.trim();
    }

    private static boolean labelCharacter(int codePoint) {
        return Character.isLetterOrDigit(codePoint)
                || codePoint == ' '
                || codePoint == '_'
                || codePoint == '-'
                || codePoint == '('
                || codePoint == ')'
                || codePoint == '（'
                || codePoint == '）'
                || codePoint == '·';
    }

    private static boolean productNameCharacter(int codePoint) {
        return labelCharacter(codePoint) || codePoint == '.';
    }
}
