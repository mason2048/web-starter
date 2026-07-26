package dev.webstarter.tooling.project;

import dev.webstarter.tooling.Checks;
import dev.webstarter.tooling.Digests;
import dev.webstarter.tooling.ToolingException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class ProjectInitializer {

    private static final Pattern SOURCE_SHA256_MARKER = Pattern.compile(
            "(?m)^/\\* source-sha256: [0-9a-f]{64} \\*/$");
    private static final List<String> IDENTITY_TOKENS = List.of(
            "启程 Web Starter",
            "WEB_STARTER_",
            "web_starter",
            "dev.webstarter",
            "dev/webstarter",
            "WebStarter",
            "webStarter",
            "web-starter",
            "webstarter",
            "Web Starter");
    private static final Pattern IDENTITY_TOKEN = Pattern.compile(
            IDENTITY_TOKENS.stream()
                    .sorted(Comparator.comparingInt(String::length).reversed())
                    .map(Pattern::quote)
                    .collect(Collectors.joining("|")));

    public record PlannedFile(Path relativePath, byte[] content, boolean executable) {
        public PlannedFile {
            relativePath = Checks.safeRelative(relativePath);
            content = content.clone();
        }

        @Override
        public byte[] content() {
            return content.clone();
        }
    }

    public record ProjectPlan(Path sourceRoot, Path output, List<PlannedFile> files, String digest) {
        public ProjectPlan {
            files = List.copyOf(files);
        }
    }

    private final TrackedTemplate trackedTemplate;

    public ProjectInitializer() {
        this(new TrackedTemplate());
    }

    ProjectInitializer(TrackedTemplate trackedTemplate) {
        this.trackedTemplate = trackedTemplate;
    }

    public ProjectPlan plan(Path sourceRoot, ProjectSpec spec) {
        Path source = realPath(Checks.existingDirectory(sourceRoot, "template source"), "template source");
        Path requestedOutput = spec.output();
        Path requestedParent = requestedOutput.getParent();
        if (requestedParent == null) {
            throw Checks.usage("output must have a parent directory");
        }
        Path parent = realPath(Checks.existingDirectory(requestedParent, "output parent"), "output parent");
        verifyEmptyOrAbsent(requestedOutput);
        Path output = Files.exists(requestedOutput, LinkOption.NOFOLLOW_LINKS)
                ? realPath(requestedOutput, "output")
                : parent.resolve(requestedOutput.getFileName()).normalize();
        if (output.equals(source) || output.startsWith(source) || source.startsWith(output)) {
            throw Checks.conflict("output and template source must not contain one another");
        }

        Map<Path, PlannedFile> files = new LinkedHashMap<>();
        for (TrackedTemplate.Entry entry : trackedTemplate.load(source)) {
            Path target = transformPath(entry.relativePath(), spec);
            byte[] content = transformContent(entry.content(), spec);
            PlannedFile planned = new PlannedFile(target, content, entry.executable());
            if (files.putIfAbsent(target, planned) != null) {
                throw Checks.conflict("identity replacement creates duplicate output path: " + target);
            }
        }
        synchronizePrivateApiContractDigest(files, spec);
        List<PlannedFile> ordered = files.values().stream()
                .sorted(Comparator.comparing(file -> file.relativePath().toString()))
                .toList();
        StringBuilder digestInput = new StringBuilder();
        for (PlannedFile file : ordered) {
            digestInput.append(file.relativePath()).append('\0')
                    .append(Digests.sha256(file.content())).append('\0')
                    .append(file.executable() ? "100755" : "100644").append('\n');
        }
        return new ProjectPlan(source, output, ordered,
                Digests.sha256(digestInput.toString().getBytes(StandardCharsets.UTF_8)));
    }

    public void apply(ProjectPlan plan) {
        verifyEmptyOrAbsent(plan.output());
        Path parent = plan.output().getParent();
        Path staging = null;
        boolean removedEmptyOutput = false;
        try {
            staging = Files.createTempDirectory(parent, ".web-starter-init-");
            for (PlannedFile file : plan.files()) {
                Path target = staging.resolve(file.relativePath()).normalize();
                if (!target.startsWith(staging)) {
                    throw Checks.conflict("planned project path escapes staging directory");
                }
                Files.createDirectories(target.getParent());
                Files.write(target, file.content());
                setExecutable(target, file.executable());
            }
            if (Files.exists(plan.output(), LinkOption.NOFOLLOW_LINKS)) {
                verifyEmptyOrAbsent(plan.output());
                Files.delete(plan.output());
                removedEmptyOutput = true;
            }
            try {
                Files.move(staging, plan.output(), StandardCopyOption.ATOMIC_MOVE);
            }
            catch (AtomicMoveNotSupportedException exception) {
                throw new IOException("atomic directory publication is not supported", exception);
            }
            staging = null;
        }
        catch (Exception failure) {
            deleteTreeQuietly(staging);
            if (removedEmptyOutput && !Files.exists(plan.output())) {
                try {
                    Files.createDirectory(plan.output());
                }
                catch (IOException restoreFailure) {
                    failure.addSuppressed(restoreFailure);
                }
            }
            if (failure instanceof ToolingException toolingException) {
                throw toolingException;
            }
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "project initialization failed without publishing a partial project", failure);
        }
        finally {
            deleteTreeQuietly(staging);
        }
    }

    private static Path transformPath(Path source, ProjectSpec spec) {
        String transformed = replaceIdentityTokens(source.toString().replace('\\', '/'), spec);
        return Checks.safeRelative(Path.of(transformed));
    }

    private static byte[] transformContent(byte[] source, ProjectSpec spec) {
        String text;
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            CharBuffer characters = decoder.decode(ByteBuffer.wrap(source));
            text = characters.toString();
            if (text.indexOf('\0') >= 0) {
                return source.clone();
            }
        }
        catch (CharacterCodingException exception) {
            return source.clone();
        }
        return replaceIdentityTokens(text, spec).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Replaces tokens found in the original template text exactly once. Replacement values are
     * never scanned again, so a legitimate derived identity that itself contains a template token
     * cannot be silently rewritten by a later rule.
     */
    private static String replaceIdentityTokens(String source, ProjectSpec spec) {
        Map<String, String> values = replacements(spec);
        Matcher matcher = IDENTITY_TOKEN.matcher(source);
        StringBuilder transformed = new StringBuilder(source.length());
        while (matcher.find()) {
            matcher.appendReplacement(transformed, Matcher.quoteReplacement(values.get(matcher.group())));
        }
        matcher.appendTail(transformed);
        return transformed.toString();
    }

    private static Map<String, String> replacements(ProjectSpec spec) {
        Map<String, String> result = new LinkedHashMap<>();
        result.put("启程 Web Starter", spec.productName());
        result.put("WEB_STARTER_", spec.environmentPrefix());
        result.put("web_starter", spec.database());
        result.put("dev.webstarter", spec.packagePrefix());
        result.put("dev/webstarter", spec.javaPath());
        result.put("WebStarter", spec.pascalName());
        result.put("webStarter", spec.camelName());
        result.put("web-starter", spec.name());
        result.put("webstarter", spec.compactName());
        result.put("Web Starter", spec.productName());
        if (!result.keySet().equals(new java.util.LinkedHashSet<>(IDENTITY_TOKENS))) {
            throw new IllegalStateException("project identity replacement tokens are out of sync");
        }
        return result;
    }

    private static void synchronizePrivateApiContractDigest(Map<Path, PlannedFile> files, ProjectSpec spec) {
        Path frontendRoot = Path.of(spec.name() + "-web");
        Path sourcePath = frontendRoot.resolve("contracts/private-api.openapi.json");
        Path generatedPath = frontendRoot.resolve("src/api/generated/privateApiContract.ts");
        PlannedFile source = files.get(sourcePath);
        PlannedFile generated = files.get(generatedPath);
        if (source == null && generated == null) {
            return;
        }
        if (source == null || generated == null) {
            throw Checks.conflict("private API contract source and generated TypeScript must both be tracked");
        }

        String generatedText = decodeUtf8(generated.content(), generatedPath);
        Matcher matcher = SOURCE_SHA256_MARKER.matcher(generatedText);
        if (!matcher.find() || matcher.find()) {
            throw Checks.conflict("generated private API contract must contain exactly one source-sha256 marker");
        }
        String marker = "/* source-sha256: " + Digests.sha256(source.content()) + " */";
        byte[] synchronizedContent = SOURCE_SHA256_MARKER.matcher(generatedText)
                .replaceFirst(Matcher.quoteReplacement(marker))
                .getBytes(StandardCharsets.UTF_8);
        files.put(generatedPath, new PlannedFile(generatedPath, synchronizedContent, generated.executable()));
    }

    private static String decodeUtf8(byte[] content, Path path) {
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(content)).toString();
        }
        catch (CharacterCodingException exception) {
            throw Checks.conflict("generated text file is not valid UTF-8: " + path);
        }
    }

    private static void verifyEmptyOrAbsent(Path output) {
        if (!Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (!Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(output)) {
            throw Checks.conflict("output must be absent or an empty non-symlink directory");
        }
        try (var entries = Files.list(output)) {
            if (entries.findAny().isPresent()) {
                throw Checks.conflict("output directory is not empty");
            }
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE, "unable to inspect output directory", exception);
        }
    }

    private static void setExecutable(Path path, boolean executable) throws IOException {
        if (!executable) {
            return;
        }
        try {
            Set<PosixFilePermission> permissions = EnumSet.noneOf(PosixFilePermission.class);
            permissions.addAll(Files.getPosixFilePermissions(path));
            permissions.add(PosixFilePermission.OWNER_EXECUTE);
            permissions.add(PosixFilePermission.GROUP_EXECUTE);
            permissions.add(PosixFilePermission.OTHERS_EXECUTE);
            Files.setPosixFilePermissions(path, permissions);
        }
        catch (UnsupportedOperationException ignored) {
            // Windows uses the generated command wrapper.
        }
    }

    private static Path realPath(Path path, String description) {
        try {
            return path.toRealPath();
        }
        catch (IOException exception) {
            throw new ToolingException(
                    ToolingException.IO_FAILURE, "unable to resolve " + description, exception);
        }
    }

    private static void deleteTreeQuietly(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                }
                catch (IOException ignored) {
                    // Staging contains generated files only and is never user-owned.
                }
            });
        }
        catch (IOException ignored) {
            // Best effort cleanup of an unpublished staging directory.
        }
    }
}
