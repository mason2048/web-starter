package dev.webstarter.tooling.dev;

import dev.webstarter.tooling.Digests;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Strict verifier for the private Surefire evidence produced by the single CRUD SDK run. */
final class McpCrudRuntimeProof {

    static final String TEST_CLASS = "dev.webstarter.mcp.acceptance.McpSdkCrudRuntimeIT";
    static final String TEST_METHOD =
            "provesEachWriteCommitsOnceAcrossConcurrencyRetryConflictAndAudit";
    static final String SOURCE_PATH =
            "web-starter-mcp/src/test/java/dev/webstarter/mcp/acceptance/McpSdkCrudRuntimeIT.java";
    static final String ROOT_POM_PATH = "pom.xml";
    static final String MODULE_POM_PATH = "web-starter-mcp/pom.xml";
    static final String REPORT_FILE = "TEST-" + TEST_CLASS + ".xml";
    static final String TRANSACTION_RECEIPT_FILE =
            "mcp-crud-transaction-receipt.properties";
    static final String PROOF_FILE = "mcp-crud-runtime-proof.properties";

    private static final Pattern KEY = Pattern.compile("[A-Za-z][A-Za-z0-9]*");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern COMMIT = Pattern.compile("[0-9a-f]{40}(?:[0-9a-f]{24})?");
    private static final Pattern VERSION = Pattern.compile(
            "[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?");
    private static final Pattern PROJECT = Pattern.compile("[a-z0-9][a-z0-9_-]{0,62}");
    private static final Pattern TRACE_PREFIX = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final long MAX_PROOF_BYTES = 32 * 1024;
    private static final long MAX_REPORT_BYTES = 2 * 1024 * 1024;
    private static final long MAX_TRANSACTION_RECEIPT_BYTES = 16 * 1024;
    private static final int MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024;
    private static final Set<String> EXPECTED_KEYS = Set.of(
            "schemaVersion",
            "testClass",
            "testMethod",
            "sourcePath",
            "sourceSha256",
            "rootPomPath",
            "rootPomSha256",
            "modulePomPath",
            "modulePomSha256",
            "reportFile",
            "reportSha256",
            "transactionReceiptFile",
            "transactionReceiptSha256",
            "candidateCommit",
            "candidateTree",
            "candidateVersion",
            "candidateTag",
            "composeProject",
            "tracePrefix",
            "startedAtEpochNs");
    private static final Set<String> TRANSACTION_RECEIPT_KEYS = Set.of(
            "schemaVersion",
            "databaseName",
            "constraintName",
            "failureTrace",
            "failureProjectCode",
            "failureIdempotencyKeyHash",
            "successTrace",
            "constraintRowsDuringFault",
            "constraintRowsAfterCleanup",
            "failedProjectRows",
            "failedOperationAuditRows",
            "failedMcpAuditRows",
            "failedMcpAuditExpectedRows",
            "failedIdempotencyRows",
            "successBusinessOperationMcpRows",
            "transactionalTableRows");
    private static final Set<String> FORBIDDEN_RESULT_ELEMENTS = Set.of(
            "failure", "error", "skipped", "flakyFailure", "flakyError",
            "rerunFailure", "rerunError");

    private McpCrudRuntimeProof() {
    }

    static Validation validate(Path workspace, Path configuredProof, Expected expected)
            throws ProofException {
        Path root = realDirectory(workspace, "workspace");
        Path requestedProof = configuredProof.toAbsolutePath().normalize();
        if (requestedProof.getParent() == null || Files.isSymbolicLink(requestedProof.getParent())) {
            throw invalid("MCP CRUD proof directory must not be a symbolic link");
        }
        Path proof = realPrivateFile(configuredProof, "MCP CRUD proof");
        if (!PROOF_FILE.equals(proof.getFileName().toString())) {
            throw invalid("MCP CRUD proof must use the fixed filename");
        }
        if (proof.startsWith(root)) {
            throw invalid("MCP CRUD proof must stay outside the Git workspace");
        }
        Path proofDirectory = proof.getParent();
        requirePrivateDirectory(proofDirectory);
        Map<String, String> values = readStrictManifest(proof);

        requireValue(values, "schemaVersion", "2");
        requireValue(values, "testClass", TEST_CLASS);
        requireValue(values, "testMethod", TEST_METHOD);
        requireValue(values, "sourcePath", SOURCE_PATH);
        requireValue(values, "rootPomPath", ROOT_POM_PATH);
        requireValue(values, "modulePomPath", MODULE_POM_PATH);
        requireValue(values, "reportFile", REPORT_FILE);
        requireValue(values, "transactionReceiptFile", TRANSACTION_RECEIPT_FILE);

        requirePattern(values, "sourceSha256", SHA256);
        requirePattern(values, "rootPomSha256", SHA256);
        requirePattern(values, "modulePomSha256", SHA256);
        requirePattern(values, "reportSha256", SHA256);
        requirePattern(values, "transactionReceiptSha256", SHA256);
        requirePattern(values, "candidateCommit", COMMIT);
        requirePattern(values, "candidateTree", COMMIT);
        requirePattern(values, "candidateVersion", VERSION);
        requirePattern(values, "composeProject", PROJECT);
        requirePattern(values, "tracePrefix", TRACE_PREFIX);
        if (!values.get("candidateTag").equals("v" + values.get("candidateVersion"))) {
            throw invalid("MCP CRUD proof candidate tag and version are inconsistent");
        }
        requireValue(values, "candidateCommit", expected.candidateCommit());
        requireValue(values, "candidateVersion", expected.candidateVersion());
        requireValue(values, "candidateTag", expected.candidateTag());
        requireValue(values, "composeProject", expected.composeProject());
        requireValue(values, "tracePrefix", expected.tracePrefix());

        long startedAtEpochNs;
        try {
            startedAtEpochNs = Long.parseLong(values.get("startedAtEpochNs"));
        }
        catch (NumberFormatException exception) {
            throw invalid("MCP CRUD proof start time is invalid", exception);
        }
        if (startedAtEpochNs <= 0) {
            throw invalid("MCP CRUD proof start time is invalid");
        }

        Path source = realRepositoryFile(root, SOURCE_PATH, "MCP CRUD test source");
        Path rootPom = realRepositoryFile(root, ROOT_POM_PATH, "root pom.xml");
        Path modulePom = realRepositoryFile(root, MODULE_POM_PATH, "MCP module pom.xml");
        GitCandidate candidate = validateGitCandidate(root, values.get("candidateCommit"),
                values.get("candidateTree"), Map.of(
                        SOURCE_PATH, source,
                        ROOT_POM_PATH, rootPom,
                        MODULE_POM_PATH, modulePom));
        requireCommittedDigest(values, "sourceSha256", candidate.files().get(SOURCE_PATH));
        requireCommittedDigest(values, "rootPomSha256", candidate.files().get(ROOT_POM_PATH));
        requireCommittedDigest(values, "modulePomSha256", candidate.files().get(MODULE_POM_PATH));

        Path report = realPrivateFile(proofDirectory.resolve(REPORT_FILE),
                "MCP CRUD Surefire report");
        if (!report.getParent().equals(proofDirectory)) {
            throw invalid("MCP CRUD proof and report must share one private directory");
        }
        requireDigest(values, "reportSha256", report);
        long reportModifiedNs;
        try {
            reportModifiedNs = Files.getLastModifiedTime(report, LinkOption.NOFOLLOW_LINKS)
                    .to(TimeUnit.NANOSECONDS);
        }
        catch (IOException exception) {
            throw invalid("cannot inspect MCP CRUD Surefire report time", exception);
        }
        if (reportModifiedNs < startedAtEpochNs) {
            throw invalid("MCP CRUD Surefire report is stale");
        }
        validateSurefireReport(report);

        Path transactionReceipt = realPrivateFile(
                proofDirectory.resolve(TRANSACTION_RECEIPT_FILE),
                "AC-16 transaction receipt");
        if (!transactionReceipt.getParent().equals(proofDirectory)) {
            throw invalid("MCP CRUD proof and transaction receipt must share one private directory");
        }
        requireDigest(values, "transactionReceiptSha256", transactionReceipt);
        long transactionReceiptModifiedNs;
        try {
            transactionReceiptModifiedNs = Files.getLastModifiedTime(
                    transactionReceipt, LinkOption.NOFOLLOW_LINKS).to(TimeUnit.NANOSECONDS);
        }
        catch (IOException exception) {
            throw invalid("cannot inspect AC-16 transaction receipt time", exception);
        }
        if (transactionReceiptModifiedNs < startedAtEpochNs) {
            throw invalid("AC-16 transaction receipt is stale");
        }
        validateTransactionReceipt(transactionReceipt, values.get("tracePrefix"));
        return new Validation(TEST_CLASS, TEST_METHOD, values.get("candidateCommit"),
                values.get("tracePrefix"));
    }

    private static Map<String, String> readStrictManifest(Path proof) throws ProofException {
        try {
            if (Files.size(proof) <= 0 || Files.size(proof) > MAX_PROOF_BYTES) {
                throw invalid("MCP CRUD proof size is invalid");
            }
            Map<String, String> values = new LinkedHashMap<>();
            List<String> lines = Files.readAllLines(proof, StandardCharsets.UTF_8);
            for (String line : lines) {
                int separator = line.indexOf('=');
                if (separator <= 0 || separator != line.lastIndexOf('=')
                        || !KEY.matcher(line.substring(0, separator)).matches()) {
                    throw invalid("MCP CRUD proof contains invalid manifest syntax");
                }
                String key = line.substring(0, separator);
                String value = line.substring(separator + 1);
                if (value.isEmpty() || !value.equals(value.trim())
                        || value.indexOf('\0') >= 0 || values.putIfAbsent(key, value) != null) {
                    throw invalid("MCP CRUD proof contains an empty, malformed, or repeated value");
                }
            }
            if (!values.keySet().equals(EXPECTED_KEYS)) {
                throw invalid("MCP CRUD proof fields differ from the fixed schema");
            }
            return Map.copyOf(values);
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("cannot read MCP CRUD proof", exception);
        }
    }

    private static void validateSurefireReport(Path report) throws ProofException {
        try {
            if (Files.size(report) <= 0 || Files.size(report) > MAX_REPORT_BYTES) {
                throw invalid("MCP CRUD Surefire report size is invalid");
            }
            byte[] payload = Files.readAllBytes(report);
            String xml = new String(payload, StandardCharsets.UTF_8);
            if (xml.toUpperCase(java.util.Locale.ROOT).contains("<!DOCTYPE")) {
                throw invalid("MCP CRUD Surefire report must not contain a DOCTYPE");
            }
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Element suite = factory.newDocumentBuilder()
                    .parse(new java.io.ByteArrayInputStream(payload)).getDocumentElement();
            if (!"testsuite".equals(suite.getTagName())
                    || !TEST_CLASS.equals(suite.getAttribute("name"))) {
                throw invalid("MCP CRUD Surefire report identifies a different test suite");
            }
            Map<String, Integer> counts = Map.of(
                    "tests", integerAttribute(suite, "tests"),
                    "failures", integerAttribute(suite, "failures"),
                    "errors", integerAttribute(suite, "errors"),
                    "skipped", integerAttribute(suite, "skipped"));
            Map<String, Integer> expected = Map.of(
                    "tests", 1, "failures", 0, "errors", 0, "skipped", 0);
            int flakes = suite.hasAttribute("flakes") ? integerAttribute(suite, "flakes") : 0;
            if (!counts.equals(expected) || flakes != 0) {
                throw invalid("MCP CRUD result is not exactly one clean passing test");
            }
            List<Element> cases = directChildren(suite, "testcase");
            if (cases.size() != 1
                    || !TEST_CLASS.equals(cases.getFirst().getAttribute("classname"))
                    || !TEST_METHOD.equals(cases.getFirst().getAttribute("name"))) {
                throw invalid("MCP CRUD Surefire report identifies a different test method");
            }
            for (String forbidden : FORBIDDEN_RESULT_ELEMENTS) {
                if (suite.getElementsByTagName(forbidden).getLength() != 0) {
                    throw invalid("MCP CRUD Surefire report contains failure, skip, retry, or flake evidence");
                }
            }
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (Exception exception) {
            throw invalid("cannot parse MCP CRUD Surefire report", exception);
        }
    }

    private static void validateTransactionReceipt(Path receipt, String tracePrefix)
            throws ProofException {
        try {
            long size = Files.size(receipt);
            if (size <= 0 || size > MAX_TRANSACTION_RECEIPT_BYTES) {
                throw invalid("AC-16 transaction receipt size is invalid");
            }
            String content = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Files.readAllBytes(receipt))).toString();
            if (content.startsWith("\uFEFF") || content.contains("\r")
                    || content.indexOf('\0') >= 0 || !content.endsWith("\n")) {
                throw invalid("AC-16 transaction receipt uses a non-canonical text encoding");
            }
            Map<String, String> values = new LinkedHashMap<>();
            for (String line : content.substring(0, content.length() - 1).split("\n", -1)) {
                int separator = line.indexOf('=');
                if (separator <= 0 || separator != line.lastIndexOf('=')
                        || !KEY.matcher(line.substring(0, separator)).matches()) {
                    throw invalid("AC-16 transaction receipt contains invalid properties syntax");
                }
                String key = line.substring(0, separator);
                String value = line.substring(separator + 1);
                if (value.isEmpty() || !value.equals(value.trim())
                        || value.chars().anyMatch(character -> character < 0x20)
                        || values.putIfAbsent(key, value) != null) {
                    throw invalid(
                            "AC-16 transaction receipt contains a malformed or repeated value");
                }
            }
            if (!values.keySet().equals(TRANSACTION_RECEIPT_KEYS)) {
                throw invalid("AC-16 transaction receipt fields differ from the fixed schema");
            }
            Map<String, String> expected = Map.ofEntries(
                    Map.entry("schemaVersion", "1"),
                    Map.entry("databaseName", "web_starter"),
                    Map.entry("constraintName", "chk_webstarter_ac16_tx_audit"),
                    Map.entry("failureTrace", tracePrefix + "-transaction-audit-failure"),
                    Map.entry("failureProjectCode", "MCP_TX_ROLLBACK"),
                    Map.entry("failureIdempotencyKeyHash",
                            "b43c6f477a4e894c03e54c53fcba80207b2f8e9804bd7525af0be2a6608586a2"),
                    Map.entry("successTrace", tracePrefix + "-create-first"),
                    Map.entry("constraintRowsDuringFault", "1"),
                    Map.entry("constraintRowsAfterCleanup", "0"),
                    Map.entry("failedProjectRows", "0"),
                    Map.entry("failedOperationAuditRows", "0"),
                    Map.entry("failedMcpAuditRows", "1"),
                    Map.entry("failedMcpAuditExpectedRows", "1"),
                    Map.entry("failedIdempotencyRows", "0"),
                    Map.entry("successBusinessOperationMcpRows", "1"),
                    Map.entry("transactionalTableRows", "4"));
            for (Map.Entry<String, String> entry : expected.entrySet()) {
                if (!entry.getValue().equals(values.get(entry.getKey()))) {
                    throw invalid("AC-16 transaction receipt " + entry.getKey()
                            + " does not prove the required value");
                }
            }
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (CharacterCodingException exception) {
            throw invalid("AC-16 transaction receipt is not valid UTF-8", exception);
        }
        catch (IOException exception) {
            throw invalid("cannot read AC-16 transaction receipt", exception);
        }
    }

    private static int integerAttribute(Element element, String name) throws ProofException {
        try {
            String value = element.getAttribute(name);
            if (!value.matches("0|[1-9][0-9]*")) {
                throw new NumberFormatException("invalid counter");
            }
            return Integer.parseInt(value);
        }
        catch (NumberFormatException exception) {
            throw invalid("MCP CRUD Surefire report has invalid counters", exception);
        }
    }

    private static List<Element> directChildren(Element parent, String name) {
        java.util.ArrayList<Element> result = new java.util.ArrayList<>();
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && name.equals(element.getTagName())) {
                result.add(element);
            }
        }
        return List.copyOf(result);
    }

    private static GitCandidate validateGitCandidate(Path root, String candidateCommit,
            String candidateTree, Map<String, Path> files) throws ProofException {
        String topLevel = gitText(root, "rev-parse", "--show-toplevel");
        Path resolvedTopLevel;
        try {
            resolvedTopLevel = Path.of(topLevel).toRealPath();
        }
        catch (IOException | RuntimeException exception) {
            throw invalid("Git top-level cannot be resolved", exception);
        }
        if (!resolvedTopLevel.equals(root)) {
            throw invalid("workspace is not the exact Git top-level");
        }
        String actualCommit = gitText(root, "rev-parse", "--verify", "HEAD^{commit}");
        if (!candidateCommit.equals(actualCommit)) {
            throw invalid("Git HEAD does not equal the MCP CRUD proof candidate commit");
        }
        String actualTree = gitText(root, "rev-parse", "--verify", "HEAD^{tree}");
        if (!candidateTree.equals(actualTree) || !COMMIT.matcher(actualTree).matches()) {
            throw invalid("Git HEAD tree does not equal the MCP CRUD proof candidate tree");
        }
        byte[] index = git(root, "ls-files", "-v", "-z");
        List<byte[]> indexEntries = splitNul(index);
        if (indexEntries.isEmpty() || indexEntries.stream().anyMatch(entry ->
                entry.length < 3 || entry[0] != 'H' || entry[1] != ' ')) {
            throw invalid("Git index contains skip-worktree, assume-unchanged, or non-cached entries");
        }
        byte[] status = git(root, "status", "--porcelain=v1", "--untracked-files=all",
                "--ignore-submodules=none");
        if (status.length != 0) {
            throw invalid("Git candidate worktree must be clean, including untracked files");
        }
        Map<String, byte[]> committed = new LinkedHashMap<>();
        for (Map.Entry<String, Path> entry : files.entrySet()) {
            byte[] bytes = committedFile(root, candidateCommit, entry.getKey());
            byte[] workspaceBytes;
            try {
                workspaceBytes = Files.readAllBytes(entry.getValue());
            }
            catch (IOException exception) {
                throw invalid("cannot read candidate workspace file " + entry.getKey(), exception);
            }
            if (!Arrays.equals(bytes, workspaceBytes)) {
                throw invalid("workspace file differs from candidate commit blob: " + entry.getKey());
            }
            committed.put(entry.getKey(), bytes);
        }
        return new GitCandidate(actualCommit, actualTree, Map.copyOf(committed));
    }

    private static byte[] committedFile(Path root, String candidateCommit, String relative)
            throws ProofException {
        byte[] rawEntry = git(root, "ls-tree", "-z", candidateCommit, "--", relative);
        List<byte[]> entries = splitNul(rawEntry);
        if (entries.size() != 1) {
            throw invalid("candidate does not contain exactly one tracked file: " + relative);
        }
        String entry = new String(entries.getFirst(), StandardCharsets.UTF_8);
        int tab = entry.indexOf('\t');
        String[] metadata = tab < 0 ? new String[0] : entry.substring(0, tab).split(" ");
        if (tab < 0 || metadata.length != 3
                || !("100644".equals(metadata[0]) || "100755".equals(metadata[0]))
                || !"blob".equals(metadata[1]) || !COMMIT.matcher(metadata[2]).matches()
                || !relative.equals(entry.substring(tab + 1))) {
            throw invalid("candidate file is not one regular Git blob: " + relative);
        }
        return git(root, "cat-file", "blob", candidateCommit + ":" + relative);
    }

    private static String gitText(Path root, String... arguments) throws ProofException {
        String value;
        try {
            value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(git(root, arguments))).toString().trim();
        }
        catch (CharacterCodingException exception) {
            throw invalid("Git candidate identity is not valid UTF-8", exception);
        }
        if (value.isEmpty() || value.indexOf('\0') >= 0 || value.contains("\n")
                || value.contains("\r")) {
            throw invalid("Git candidate identity output is invalid");
        }
        return value;
    }

    private static byte[] git(Path root, String... arguments) throws ProofException {
        java.util.ArrayList<String> command = new java.util.ArrayList<>();
        command.add("git");
        command.add("-c");
        command.add("core.fsmonitor=false");
        command.add("-c");
        command.add("core.untrackedCache=false");
        command.add("-C");
        command.add(root.toString());
        command.addAll(List.of(arguments));
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            for (String name : List.of(
                    "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                    "GIT_OBJECT_DIRECTORY",
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES")) {
                builder.environment().remove(name);
            }
            builder.environment().put("GIT_OPTIONAL_LOCKS", "0");
            process = builder.start();
            byte[] output;
            try (InputStream input = process.getInputStream()) {
                output = input.readNBytes(MAX_GIT_OUTPUT_BYTES + 1);
            }
            if (output.length > MAX_GIT_OUTPUT_BYTES) {
                process.destroyForcibly();
                throw invalid("Git candidate verification output is unexpectedly large");
            }
            int exit = process.waitFor();
            if (exit != 0) {
                throw invalid("Git could not verify the MCP CRUD candidate");
            }
            return output;
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("Git is required to verify the MCP CRUD candidate", exception);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw invalid("Git candidate verification was interrupted", exception);
        }
        finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private static List<byte[]> splitNul(byte[] input) {
        java.util.ArrayList<byte[]> result = new java.util.ArrayList<>();
        int start = 0;
        for (int index = 0; index < input.length; index++) {
            if (input[index] == 0) {
                if (index > start) {
                    result.add(Arrays.copyOfRange(input, start, index));
                }
                start = index + 1;
            }
        }
        if (start < input.length) {
            result.add(Arrays.copyOfRange(input, start, input.length));
        }
        return List.copyOf(result);
    }

    private static Path realDirectory(Path configured, String label) throws ProofException {
        try {
            Path normalized = configured.toAbsolutePath().normalize();
            if (Files.isSymbolicLink(normalized)
                    || !Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw invalid(label + " must be a non-symlink directory");
            }
            return normalized.toRealPath();
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("cannot resolve " + label, exception);
        }
    }

    private static Path realPrivateFile(Path configured, String label) throws ProofException {
        try {
            Path normalized = configured.toAbsolutePath().normalize();
            if (Files.isSymbolicLink(normalized)
                    || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw invalid(label + " must be an existing non-symlink regular file");
            }
            Path real = normalized.toRealPath();
            requirePrivatePermissions(real, label);
            return real;
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("cannot resolve " + label, exception);
        }
    }

    private static Path realRepositoryFile(Path root, String relative, String label)
            throws ProofException {
        Path configured = root.resolve(relative).normalize();
        try {
            if (!configured.startsWith(root) || Files.isSymbolicLink(configured)
                    || !Files.isRegularFile(configured, LinkOption.NOFOLLOW_LINKS)) {
                throw invalid(label + " must be a non-symlink repository file");
            }
            Path real = configured.toRealPath();
            if (!real.startsWith(root)) {
                throw invalid(label + " escaped the repository");
            }
            return real;
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("cannot resolve " + label, exception);
        }
    }

    private static void requirePrivateDirectory(Path directory) throws ProofException {
        try {
            if (Files.isSymbolicLink(directory)
                    || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                throw invalid("MCP CRUD proof directory must be a non-symlink directory");
            }
            if (supportsPosix(directory)) {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                        directory, LinkOption.NOFOLLOW_LINKS);
                Set<PosixFilePermission> expected = Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE);
                if (!permissions.equals(expected)) {
                    throw invalid("MCP CRUD proof directory must be private (chmod 700)");
                }
            }
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("cannot inspect MCP CRUD proof directory permissions", exception);
        }
    }

    private static void requirePrivatePermissions(Path file, String label) throws IOException,
            ProofException {
        if (!supportsPosix(file)) {
            return;
        }
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                file, LinkOption.NOFOLLOW_LINKS);
        Set<PosixFilePermission> expected = Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE);
        if (!permissions.equals(expected)) {
            throw invalid(label + " must be private (chmod 600)");
        }
    }

    private static boolean supportsPosix(Path path) throws IOException {
        return Files.getFileStore(path).supportsFileAttributeView("posix");
    }

    private static void requireDigest(Map<String, String> values, String key, Path path)
            throws ProofException {
        try {
            String actual = Digests.sha256(Files.readAllBytes(path));
            if (!actual.equals(values.get(key))) {
                throw invalid("MCP CRUD proof hash mismatch for " + key);
            }
        }
        catch (ProofException exception) {
            throw exception;
        }
        catch (IOException exception) {
            throw invalid("cannot hash MCP CRUD proof input for " + key, exception);
        }
    }

    private static void requireCommittedDigest(Map<String, String> values, String key,
            byte[] committed) throws ProofException {
        String actual = Digests.sha256(committed);
        if (!actual.equals(values.get(key))) {
            throw invalid("MCP CRUD proof hash mismatch for " + key);
        }
    }

    private static void requireValue(Map<String, String> values, String key, String expected)
            throws ProofException {
        if (!expected.equals(values.get(key))) {
            throw invalid("MCP CRUD proof value mismatch for " + key);
        }
    }

    private static void requirePattern(Map<String, String> values, String key, Pattern pattern)
            throws ProofException {
        String value = values.get(key);
        if (value == null || !pattern.matcher(value).matches()) {
            throw invalid("MCP CRUD proof value is invalid for " + key);
        }
    }

    private static ProofException invalid(String message) {
        return new ProofException(message, null);
    }

    private static ProofException invalid(String message, Throwable cause) {
        return new ProofException(message, cause);
    }

    record Expected(String candidateCommit, String candidateVersion, String candidateTag,
                    String composeProject, String tracePrefix) {
    }

    record Validation(String testClass, String testMethod, String candidateCommit,
                      String tracePrefix) {
    }

    private record GitCandidate(String commit, String tree, Map<String, byte[]> files) {
        private GitCandidate {
            Map<String, byte[]> copied = new LinkedHashMap<>();
            files.forEach((name, content) -> copied.put(name, content.clone()));
            files = Map.copyOf(copied);
        }

        @Override
        public Map<String, byte[]> files() {
            Map<String, byte[]> copied = new LinkedHashMap<>();
            files.forEach((name, content) -> copied.put(name, content.clone()));
            return Map.copyOf(copied);
        }
    }

    static final class ProofException extends Exception {
        private ProofException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
