package dev.webstarter.tooling.dev;

import dev.webstarter.tooling.Digests;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpCrudRuntimeProofTest {

    @TempDir
    Path temporary;

    @Test
    void validatesOnePrivatePassingReportAgainstSourcePomsAndCandidateIdentity() throws Exception {
        Fixture fixture = new Fixture(temporary);

        McpCrudRuntimeProof.Validation validation = McpCrudRuntimeProof.validate(
                fixture.workspace, fixture.proof, fixture.expected());

        assertEquals(McpCrudRuntimeProof.TEST_CLASS, validation.testClass());
        assertEquals(McpCrudRuntimeProof.TEST_METHOD, validation.testMethod());
        assertEquals(fixture.commit, validation.candidateCommit());
        assertEquals("release-sdk", validation.tracePrefix());
    }

    @Test
    void rejectsSkippedFailedRetriedOrDifferentSurefireResultsEvenWithFreshReportHash()
            throws Exception {
        Fixture skipped = new Fixture(temporary.resolve("skipped"));
        skipped.setReport(skipped.xml.replace("tests=\"1\"", "tests=\"1\"")
                .replace("skipped=\"0\"", "skipped=\"1\""));
        skipped.refreshManifest();
        assertRejected(skipped, "one clean passing test");

        Fixture failure = new Fixture(temporary.resolve("failure"));
        failure.setReport(failure.xml.replace("failures=\"0\"", "failures=\"1\""));
        failure.refreshManifest();
        assertRejected(failure, "one clean passing test");

        Fixture retry = new Fixture(temporary.resolve("retry"));
        retry.setReport(retry.xml.replace("flakes=\"0\"", "flakes=\"1\""));
        retry.refreshManifest();
        assertRejected(retry, "one clean passing test");

        Fixture wrongClass = new Fixture(temporary.resolve("wrong-class"));
        wrongClass.setReport(wrongClass.xml.replace(McpCrudRuntimeProof.TEST_CLASS,
                "dev.webstarter.mcp.acceptance.OtherRuntimeIT"));
        wrongClass.refreshManifest();
        assertRejected(wrongClass, "different test suite");
    }

    @Test
    void rejectsSourceRootPomModulePomReportAndCandidateDrift() throws Exception {
        Fixture source = new Fixture(temporary.resolve("source"));
        source.values.put("sourceSha256", "0".repeat(64));
        source.writeManifest();
        assertRejected(source, "sourceSha256");

        Fixture rootPom = new Fixture(temporary.resolve("root-pom"));
        rootPom.values.put("rootPomSha256", "0".repeat(64));
        rootPom.writeManifest();
        assertRejected(rootPom, "rootPomSha256");

        Fixture modulePom = new Fixture(temporary.resolve("module-pom"));
        modulePom.values.put("modulePomSha256", "0".repeat(64));
        modulePom.writeManifest();
        assertRejected(modulePom, "modulePomSha256");

        Fixture report = new Fixture(temporary.resolve("report"));
        Files.writeString(report.report, report.xml.replace("time=\"0.1\"", "time=\"0.2\""));
        assertRejected(report, "reportSha256");

        Fixture candidate = new Fixture(temporary.resolve("candidate"));
        candidate.values.put("candidateCommit", "b".repeat(40));
        candidate.values.put("candidateTree", "c".repeat(40));
        candidate.writeManifest();
        McpCrudRuntimeProof.Expected wrong = new McpCrudRuntimeProof.Expected(
                "b".repeat(40), "2.0.0", "v2.0.0",
                "web-starter-release-1", "release-sdk");
        McpCrudRuntimeProof.ProofException exception = assertThrows(
                McpCrudRuntimeProof.ProofException.class,
                () -> McpCrudRuntimeProof.validate(candidate.workspace, candidate.proof, wrong));
        assertTrue(exception.getMessage().contains("Git HEAD"), exception.getMessage());
    }

    @Test
    void rejectsTransactionReceiptHashAndSemanticDrift() throws Exception {
        Fixture hashDrift = new Fixture(temporary.resolve("transaction-receipt-hash"));
        Files.writeString(hashDrift.transactionReceipt,
                hashDrift.transactionReceiptContent.replace(
                        "failedProjectRows=0", "failedProjectRows=1"));
        assertRejected(hashDrift, "transactionReceiptSha256");

        Fixture semanticDrift = new Fixture(temporary.resolve("transaction-receipt-semantic"));
        semanticDrift.setTransactionReceipt(
                semanticDrift.transactionReceiptContent.replace(
                        "failedProjectRows=0", "failedProjectRows=1"));
        semanticDrift.refreshTransactionReceiptManifest();
        assertRejected(semanticDrift, "failedProjectRows");
    }

    @Test
    void rejectsRepeatedFieldsStaleReportsAndNonPrivateEvidence() throws Exception {
        Fixture repeated = new Fixture(temporary.resolve("repeated"));
        Files.writeString(repeated.proof,
                Files.readString(repeated.proof) + "candidateCommit=" + repeated.commit + "\n");
        assertRejected(repeated, "repeated");

        Fixture stale = new Fixture(temporary.resolve("stale"));
        stale.values.put("startedAtEpochNs", Long.toString(Long.MAX_VALUE));
        stale.writeManifest();
        assertRejected(stale, "stale");

        Fixture broad = new Fixture(temporary.resolve("broad"));
        if (posix(broad.proof)) {
            Files.setPosixFilePermissions(broad.proof, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ));
            assertRejected(broad, "private");
        }
    }

    @Test
    void rejectsDirtyUntrackedAndHiddenIndexState() throws Exception {
        Fixture dirty = new Fixture(temporary.resolve("dirty"));
        Files.writeString(dirty.source, "// dirty workspace source\n");
        assertRejected(dirty, "worktree must be clean");

        Fixture untracked = new Fixture(temporary.resolve("untracked"));
        Files.writeString(untracked.workspace.resolve("untracked.txt"), "not candidate material\n");
        assertRejected(untracked, "worktree must be clean");

        Fixture hidden = new Fixture(temporary.resolve("hidden"));
        git(hidden.workspace, "update-index", "--assume-unchanged",
                McpCrudRuntimeProof.SOURCE_PATH);
        assertRejected(hidden, "Git index contains");
    }

    private static void assertRejected(Fixture fixture, String message) {
        McpCrudRuntimeProof.ProofException exception = assertThrows(
                McpCrudRuntimeProof.ProofException.class,
                () -> McpCrudRuntimeProof.validate(
                        fixture.workspace, fixture.proof, fixture.expected()));
        assertTrue(exception.getMessage().contains(message), exception.getMessage());
    }

    private static final class Fixture {
        private final Path workspace;
        private final Path source;
        private final Path rootPom;
        private final Path modulePom;
        private final Path report;
        private final Path transactionReceipt;
        private final Path proof;
        private final Map<String, String> values = new LinkedHashMap<>();
        private final String commit;
        private final String tree;
        private String xml;
        private String transactionReceiptContent;

        private Fixture(Path parent) throws Exception {
            Files.createDirectories(parent);
            workspace = Files.createDirectory(parent.resolve("workspace"));
            rootPom = workspace.resolve(McpCrudRuntimeProof.ROOT_POM_PATH);
            Files.writeString(rootPom, "<project/>\n");
            source = workspace.resolve(McpCrudRuntimeProof.SOURCE_PATH);
            Files.createDirectories(source.getParent());
            Files.writeString(source, "// fixed acceptance source\n");
            modulePom = workspace.resolve(McpCrudRuntimeProof.MODULE_POM_PATH);
            Files.writeString(modulePom, "<project/>\n");
            git(workspace, "init", "-q");
            git(workspace, "config", "user.email", "proof-test@example.invalid");
            git(workspace, "config", "user.name", "Proof Test");
            git(workspace, "add", ".");
            git(workspace, "commit", "-q", "-m", "candidate fixture");
            commit = gitText(workspace, "rev-parse", "HEAD^{commit}");
            tree = gitText(workspace, "rev-parse", "HEAD^{tree}");

            Path proofDirectory = Files.createDirectory(parent.resolve("proof"));
            privateDirectory(proofDirectory);
            report = proofDirectory.resolve(McpCrudRuntimeProof.REPORT_FILE);
            xml = """
                    <?xml version="1.0" encoding="UTF-8"?>
                    <testsuite name="dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"
                      time="0.1" tests="1" failures="0" errors="0" skipped="0" flakes="0">
                      <testcase
                        name="provesEachWriteCommitsOnceAcrossConcurrencyRetryConflictAndAudit"
                        classname="dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT"/>
                    </testsuite>
                    """;
            setReport(xml);
            transactionReceipt = proofDirectory.resolve(
                    McpCrudRuntimeProof.TRANSACTION_RECEIPT_FILE);
            transactionReceiptContent = """
                    schemaVersion=1
                    databaseName=web_starter
                    constraintName=chk_webstarter_ac16_tx_audit
                    failureTrace=release-sdk-transaction-audit-failure
                    failureProjectCode=MCP_TX_ROLLBACK
                    failureIdempotencyKeyHash=b43c6f477a4e894c03e54c53fcba80207b2f8e9804bd7525af0be2a6608586a2
                    successTrace=release-sdk-create-first
                    constraintRowsDuringFault=1
                    constraintRowsAfterCleanup=0
                    failedProjectRows=0
                    failedOperationAuditRows=0
                    failedMcpAuditRows=1
                    failedMcpAuditExpectedRows=1
                    failedIdempotencyRows=0
                    successBusinessOperationMcpRows=1
                    transactionalTableRows=4
                    """;
            setTransactionReceipt(transactionReceiptContent);
            proof = proofDirectory.resolve(McpCrudRuntimeProof.PROOF_FILE);
            values.put("schemaVersion", "2");
            values.put("testClass", McpCrudRuntimeProof.TEST_CLASS);
            values.put("testMethod", McpCrudRuntimeProof.TEST_METHOD);
            values.put("sourcePath", McpCrudRuntimeProof.SOURCE_PATH);
            values.put("sourceSha256", digest(source));
            values.put("rootPomPath", McpCrudRuntimeProof.ROOT_POM_PATH);
            values.put("rootPomSha256", digest(rootPom));
            values.put("modulePomPath", McpCrudRuntimeProof.MODULE_POM_PATH);
            values.put("modulePomSha256", digest(modulePom));
            values.put("reportFile", McpCrudRuntimeProof.REPORT_FILE);
            values.put("reportSha256", digest(report));
            values.put("transactionReceiptFile",
                    McpCrudRuntimeProof.TRANSACTION_RECEIPT_FILE);
            values.put("transactionReceiptSha256", digest(transactionReceipt));
            values.put("candidateCommit", commit);
            values.put("candidateTree", tree);
            values.put("candidateVersion", "2.0.0");
            values.put("candidateTag", "v2.0.0");
            values.put("composeProject", "web-starter-release-1");
            values.put("tracePrefix", "release-sdk");
            values.put("startedAtEpochNs", "1");
            writeManifest();
        }

        private McpCrudRuntimeProof.Expected expected() {
            return new McpCrudRuntimeProof.Expected(commit, "2.0.0", "v2.0.0",
                    "web-starter-release-1", "release-sdk");
        }

        private void setReport(String content) throws IOException {
            xml = content;
            Files.writeString(report, content);
            privateFile(report);
        }

        private void refreshManifest() throws IOException {
            values.put("reportSha256", digest(report));
            writeManifest();
        }

        private void setTransactionReceipt(String content) throws IOException {
            transactionReceiptContent = content;
            Files.writeString(transactionReceipt, content);
            privateFile(transactionReceipt);
        }

        private void refreshTransactionReceiptManifest() throws IOException {
            values.put("transactionReceiptSha256", digest(transactionReceipt));
            writeManifest();
        }

        private void writeManifest() throws IOException {
            StringBuilder content = new StringBuilder();
            values.forEach((key, value) -> content.append(key).append('=').append(value).append('\n'));
            Files.writeString(proof, content);
            privateFile(proof);
        }
    }

    private static String digest(Path path) throws IOException {
        return Digests.sha256(Files.readAllBytes(path));
    }

    private static void privateFile(Path path) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        }
    }

    private static void privateDirectory(Path path) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        }
    }

    private static boolean posix(Path path) throws IOException {
        FileStore store = Files.getFileStore(path);
        return store.supportsFileAttributeView("posix");
    }

    private static String gitText(Path root, String... arguments) throws Exception {
        return git(root, arguments).trim();
    }

    private static String git(Path root, String... arguments) throws Exception {
        java.util.ArrayList<String> command = new java.util.ArrayList<>();
        command.add("git");
        command.add("-C");
        command.add(root.toString());
        command.addAll(java.util.List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IOException("git fixture command failed: " + output);
        }
        return output;
    }
}
