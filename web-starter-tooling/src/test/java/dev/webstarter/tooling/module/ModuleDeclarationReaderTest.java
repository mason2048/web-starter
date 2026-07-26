package dev.webstarter.tooling.module;

import dev.webstarter.tooling.ToolingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModuleDeclarationReaderTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void readsVersionedFixedSchemaAndAppliesModuleDefaults() throws Exception {
        Path declaration = write("""
                {
                  "schemaVersion": 1,
                  "name": "asset",
                  "label": "资产",
                  "migrationVersion": "202607190001",
                  "permissionIdBase": 5100,
                  "menuId": 6100
                }
                """);

        ModuleSpec spec = ModuleDeclarationReader.read(declaration);

        assertEquals("asset", spec.name());
        assertEquals("assets", spec.plural());
        assertEquals("biz_asset", spec.table());
        assertEquals("/assets", spec.route());
        assertEquals(202607190001L, Long.parseLong(spec.migrationVersion()));
        assertEquals(5100L, spec.permissionIdBase());
        assertEquals(6100L, spec.menuId());
        assertFalse(spec.withMcp());
    }

    @Test
    void rejectsUnknownPathOrExecutionFields() throws Exception {
        ToolingException failure = assertInvalid("""
                {
                  "schemaVersion": 1,
                  "name": "asset",
                  "label": "资产",
                  "migrationVersion": "4",
                  "permissionIdBase": 5100,
                  "menuId": 6100,
                  "outputPath": "../../outside"
                }
                """);

        assertTrue(failure.getMessage().contains("unknown field"));
        assertFalse(failure.getMessage().contains("../../outside"));

        ToolingException hiddenMcp = assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100,"withMcp":true}
                """);
        assertTrue(hiddenMcp.getMessage().contains("unknown field"));
    }

    @Test
    void rejectsDuplicateFieldsNestedValuesAndTrailingContent() throws Exception {
        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","name":"other","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """).getMessage().contains("duplicate field"));

        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":{"text":"资产"},
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """).getMessage().contains("nested objects"));

        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100} []
                """).getMessage().contains("content after"));
    }

    @Test
    void rejectsUnsupportedVersionWrongTypesAndExpressions() throws Exception {
        assertTrue(assertInvalid("""
                {"schemaVersion":2,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """).getMessage().contains("schemaVersion"));

        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":4,"permissionIdBase":5100,"menuId":6100}
                """).getMessage().contains("migrationVersion"));

        ToolingException expression = assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"${ENV_SECRET}",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """);
        assertTrue(expression.getMessage().contains("expression syntax"));
        assertFalse(expression.getMessage().contains("ENV_SECRET"));

        ToolingException sourceInjection = assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"x\\\\' ); DROP TABLE sys_user; --",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """);
        assertTrue(sourceInjection.getMessage().contains("module label"));

        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":٥١٠٠,"menuId":6100}
                """).getMessage().contains("unsupported value type"));
    }

    @Test
    void rejectsOversizedAndSymbolicLinkDeclarations() throws Exception {
        Path oversized = temporaryDirectory.resolve("oversized.json");
        Files.write(oversized, new byte[ModuleDeclarationReader.MAX_DECLARATION_BYTES + 1]);

        ToolingException sizeFailure = assertThrows(
                ToolingException.class, () -> ModuleDeclarationReader.read(oversized));
        assertEquals(ToolingException.USAGE, sizeFailure.exitCode());

        Path target = write(validDeclaration());
        Path link = temporaryDirectory.resolve("module-link.json");
        Files.createSymbolicLink(link, target.getFileName());

        ToolingException linkFailure = assertThrows(
                ToolingException.class, () -> ModuleDeclarationReader.read(link));
        assertEquals(ToolingException.PREREQUISITE, linkFailure.exitCode());
    }

    @Test
    void rejectsJsonExtensionsInvalidUtf8AndEscapedParserTricks() throws Exception {
        assertTrue(assertInvalid("""
                {// comment
                 "schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """).getMessage().contains("field names"));
        assertTrue(assertInvalid("""
                {'schemaVersion':1,'name':'asset','label':'资产',
                 'migrationVersion':'4','permissionIdBase':5100,'menuId':6100}
                """).getMessage().contains("field names"));
        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100,}
                """).getMessage().contains("trailing commas"));
        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5.1e3,"menuId":6100}
                """).getMessage().contains("integer numbers"));

        String escapedName = "\\" + "u006eame";
        assertTrue(assertInvalid("""
                {"schemaVersion":1,"name":"asset","%s":"other","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """.formatted(escapedName)).getMessage().contains("duplicate field"));

        String unpairedSurrogate = "\\" + "uD800";
        assertTrue(assertInvalid(validDeclaration().replace("资产", unpairedSurrogate))
                .getMessage().contains("unpaired Unicode surrogate"));

        String nonAsciiUnicodeEscape = "\\" + "u٠٠٤1";
        assertTrue(assertInvalid(validDeclaration().replace("资产", nonAsciiUnicodeEscape))
                .getMessage().contains("invalid Unicode escape"));

        Path invalidUtf8 = temporaryDirectory.resolve("invalid-utf8.json");
        Files.write(invalidUtf8, new byte[]{'{', '"', (byte) 0xff});
        ToolingException encoding = assertThrows(
                ToolingException.class, () -> ModuleDeclarationReader.read(invalidUtf8));
        assertEquals(ToolingException.USAGE, encoding.exitCode());
        assertTrue(encoding.getMessage().contains("valid UTF-8"));
    }

    private ToolingException assertInvalid(String content) throws Exception {
        Path declaration = write(content);
        ToolingException failure = assertThrows(
                ToolingException.class, () -> ModuleDeclarationReader.read(declaration));
        assertEquals(ToolingException.USAGE, failure.exitCode());
        return failure;
    }

    private Path write(String content) throws Exception {
        Path declaration = temporaryDirectory.resolve("module-" + System.nanoTime() + ".json");
        Files.writeString(declaration, content, StandardCharsets.UTF_8);
        return declaration;
    }

    private static String validDeclaration() {
        return """
                {"schemaVersion":1,"name":"asset","label":"资产",
                 "migrationVersion":"4","permissionIdBase":5100,"menuId":6100}
                """;
    }
}
