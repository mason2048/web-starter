package dev.webstarter.tooling.module;

import dev.webstarter.tooling.Checks;
import dev.webstarter.tooling.ToolingException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Reads the fixed, non-executable JSON contract accepted by the module generator. */
public final class ModuleDeclarationReader {

    static final int MAX_DECLARATION_BYTES = 16 * 1024;

    private static final List<String> REQUIRED_FIELDS = List.of(
            "schemaVersion", "name", "label", "migrationVersion", "permissionIdBase", "menuId");
    private static final Set<String> ALLOWED_FIELDS = Set.of(
            "schemaVersion", "name", "label", "plural", "table", "route",
            "migrationVersion", "permissionIdBase", "menuId");
    private static final List<String> EXPRESSION_MARKERS = List.of(
            "${", "#{", "{{", "}}", "<%", "%>", "$(", "`");

    private ModuleDeclarationReader() {
    }

    public static ModuleSpec read(String source) {
        try {
            return read(Path.of(source));
        }
        catch (InvalidPathException exception) {
            throw Checks.usage("module declaration path is invalid");
        }
    }

    public static ModuleSpec read(Path source) {
        Path declaration = source.toAbsolutePath().normalize();
        if (!Files.isRegularFile(declaration, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(declaration)) {
            throw new ToolingException(
                    ToolingException.PREREQUISITE,
                    "module declaration must be an existing non-symlink regular file");
        }

        byte[] bytes;
        try (var channel = Files.newByteChannel(
                declaration, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = Channels.newInputStream(channel).readNBytes(MAX_DECLARATION_BYTES + 1);
        }
        catch (IOException exception) {
            throw new ToolingException(
                    ToolingException.IO_FAILURE, "unable to read module declaration", exception);
        }
        if (bytes.length > MAX_DECLARATION_BYTES) {
            throw invalid("file exceeds 16384 bytes");
        }

        String document = decodeUtf8(bytes);
        Map<String, JsonValue> values = new StrictJsonObjectParser(document).parse();
        for (String field : values.keySet()) {
            if (!ALLOWED_FIELDS.contains(field)) {
                throw invalid("unknown field");
            }
        }
        for (String field : REQUIRED_FIELDS) {
            if (!values.containsKey(field)) {
                throw invalid("required field '" + field + "' is missing");
            }
        }

        String schemaVersion = requiredInteger(values, "schemaVersion");
        if (!"1".equals(schemaVersion)) {
            throw invalid("schemaVersion must be the integer 1");
        }

        return ModuleSpec.from(
                requiredString(values, "name"),
                requiredString(values, "label"),
                optionalString(values, "plural"),
                optionalString(values, "table"),
                optionalString(values, "route"),
                requiredString(values, "migrationVersion"),
                requiredInteger(values, "permissionIdBase"),
                requiredInteger(values, "menuId"),
                false);
    }

    private static String decodeUtf8(byte[] bytes) {
        try {
            CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            return decoded.toString();
        }
        catch (CharacterCodingException exception) {
            throw invalid("file must be valid UTF-8");
        }
    }

    private static String requiredString(Map<String, JsonValue> values, String field) {
        JsonValue value = values.get(field);
        if (value == null || value.type() != JsonType.STRING) {
            throw invalid("field '" + field + "' must be a string");
        }
        rejectExpression(value.value());
        return value.value();
    }

    private static String optionalString(Map<String, JsonValue> values, String field) {
        JsonValue value = values.get(field);
        if (value == null) {
            return null;
        }
        if (value.type() != JsonType.STRING) {
            throw invalid("field '" + field + "' must be a string");
        }
        rejectExpression(value.value());
        return value.value();
    }

    private static String requiredInteger(Map<String, JsonValue> values, String field) {
        JsonValue value = values.get(field);
        if (value == null || value.type() != JsonType.INTEGER) {
            throw invalid("field '" + field + "' must be an integer");
        }
        return value.value();
    }

    private static void rejectExpression(String value) {
        if (EXPRESSION_MARKERS.stream().anyMatch(value::contains)) {
            throw invalid("template and expression syntax is not allowed");
        }
    }

    private static ToolingException invalid(String detail) {
        return Checks.usage("invalid module declaration: " + detail);
    }

    private enum JsonType {
        STRING,
        INTEGER,
        BOOLEAN
    }

    private record JsonValue(JsonType type, String value) {
    }

    /** Minimal strict parser: one JSON object whose values are strings, integers, or booleans. */
    private static final class StrictJsonObjectParser {

        private final String document;
        private int index;

        private StrictJsonObjectParser(String document) {
            this.document = document;
        }

        private Map<String, JsonValue> parse() {
            skipWhitespace();
            expect('{');
            Map<String, JsonValue> result = new LinkedHashMap<>();
            skipWhitespace();
            if (consume('}')) {
                requireEnd();
                return result;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw malformed("object field names must be strings");
                }
                String name = string();
                if (result.containsKey(name)) {
                    throw invalid("duplicate field");
                }
                skipWhitespace();
                expect(':');
                skipWhitespace();
                result.put(name, scalar());
                skipWhitespace();
                if (consume('}')) {
                    requireEnd();
                    return result;
                }
                expect(',');
                skipWhitespace();
                if (peek() == '}') {
                    throw malformed("trailing commas are not allowed");
                }
            }
        }

        private JsonValue scalar() {
            char current = peek();
            if (current == '"') {
                return new JsonValue(JsonType.STRING, string());
            }
            if (current == 't') {
                literal("true");
                return new JsonValue(JsonType.BOOLEAN, "true");
            }
            if (current == 'f') {
                literal("false");
                return new JsonValue(JsonType.BOOLEAN, "false");
            }
            if (current == '{' || current == '[') {
                throw invalid("nested objects and arrays are not allowed");
            }
            if (current == 'n') {
                throw invalid("null values are not allowed");
            }
            if (current == '-' || isAsciiDigit(current)) {
                return new JsonValue(JsonType.INTEGER, integer());
            }
            throw malformed("unsupported value type");
        }

        private String string() {
            expect('"');
            StringBuilder result = new StringBuilder();
            while (index < document.length()) {
                char current = document.charAt(index++);
                if (current == '"') {
                    if (containsUnpairedSurrogate(result)) {
                        throw malformed("unpaired Unicode surrogate is not allowed");
                    }
                    return result.toString();
                }
                if (current < 0x20) {
                    throw malformed("unescaped control character in string");
                }
                if (current != '\\') {
                    result.append(current);
                    continue;
                }
                if (index >= document.length()) {
                    throw malformed("unterminated escape sequence");
                }
                char escaped = document.charAt(index++);
                switch (escaped) {
                    case '"', '\\', '/' -> result.append(escaped);
                    case 'b' -> result.append('\b');
                    case 'f' -> result.append('\f');
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    case 'u' -> result.append(unicodeEscape());
                    default -> throw malformed("invalid string escape");
                }
            }
            throw malformed("unterminated string");
        }

        private boolean containsUnpairedSurrogate(CharSequence value) {
            for (int offset = 0; offset < value.length(); offset++) {
                char current = value.charAt(offset);
                if (Character.isHighSurrogate(current)) {
                    if (++offset >= value.length() || !Character.isLowSurrogate(value.charAt(offset))) {
                        return true;
                    }
                }
                else if (Character.isLowSurrogate(current)) {
                    return true;
                }
            }
            return false;
        }

        private char unicodeEscape() {
            if (index + 4 > document.length()) {
                throw malformed("incomplete Unicode escape");
            }
            int value = 0;
            for (int offset = 0; offset < 4; offset++) {
                int digit = asciiHexDigit(document.charAt(index++));
                if (digit < 0) {
                    throw malformed("invalid Unicode escape");
                }
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private int asciiHexDigit(char value) {
            if (value >= '0' && value <= '9') {
                return value - '0';
            }
            if (value >= 'a' && value <= 'f') {
                return value - 'a' + 10;
            }
            if (value >= 'A' && value <= 'F') {
                return value - 'A' + 10;
            }
            return -1;
        }

        private String integer() {
            int start = index;
            consume('-');
            if (index >= document.length() || !isAsciiDigit(document.charAt(index))) {
                throw malformed("invalid integer");
            }
            if (document.charAt(index) == '0') {
                index++;
                if (index < document.length() && isAsciiDigit(document.charAt(index))) {
                    throw malformed("integers cannot contain leading zeroes");
                }
            }
            else {
                while (index < document.length() && isAsciiDigit(document.charAt(index))) {
                    index++;
                }
            }
            if (index < document.length()) {
                char next = document.charAt(index);
                if (next == '.' || next == 'e' || next == 'E') {
                    throw invalid("only integer numbers are allowed");
                }
            }
            return document.substring(start, index);
        }

        private boolean isAsciiDigit(char value) {
            return value >= '0' && value <= '9';
        }

        private void literal(String expected) {
            if (!document.startsWith(expected, index)) {
                throw malformed("invalid literal");
            }
            index += expected.length();
        }

        private void requireEnd() {
            skipWhitespace();
            if (index != document.length()) {
                throw malformed("content after the top-level object is not allowed");
            }
        }

        private void skipWhitespace() {
            while (index < document.length()) {
                char current = document.charAt(index);
                if (current != ' ' && current != '\t' && current != '\r' && current != '\n') {
                    return;
                }
                index++;
            }
        }

        private char peek() {
            if (index >= document.length()) {
                throw malformed("unexpected end of document");
            }
            return document.charAt(index);
        }

        private boolean consume(char expected) {
            if (index < document.length() && document.charAt(index) == expected) {
                index++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!consume(expected)) {
                throw malformed("expected '" + expected + "'");
            }
        }

        private ToolingException malformed(String detail) {
            return invalid(detail + " at character " + index);
        }
    }
}
