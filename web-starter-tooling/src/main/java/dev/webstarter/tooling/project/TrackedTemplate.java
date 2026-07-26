package dev.webstarter.tooling.project;

import dev.webstarter.tooling.Checks;
import dev.webstarter.tooling.ToolingException;

import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Reads a clean Git index as the project template allowlist. */
public final class TrackedTemplate {

    private static final Pattern DATED_ACCEPTANCE = Pattern.compile(
            "docs/acceptance/.*acceptance-[0-9]{4}-[0-9]{2}-[0-9]{2}.*",
            Pattern.CASE_INSENSITIVE);
    private static final Set<String> SECRET_SUFFIXES = Set.of(
            ".cer", ".crt", ".der", ".jks", ".kdbx", ".key", ".keystore", ".p12", ".pem", ".pfx");
    private static final Set<String> SECRET_NAMES = Set.of(
            "credentials.json", "service-account.json", "service_account.json",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519");
    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of(
            ".git", ".pnpm-store", ".vite", "coverage", "dist", "node_modules",
            "playwright-report", "target", "test-results");

    public record Entry(Path relativePath, byte[] content, boolean executable) {
        public Entry {
            relativePath = Checks.safeRelative(relativePath);
            content = content.clone();
        }

        @Override
        public byte[] content() {
            return content.clone();
        }
    }

    public List<Entry> load(Path sourceRoot) {
        Path root = Checks.existingDirectory(sourceRoot, "template source");
        Path gitMetadata = root.resolve(".git");
        if (!Files.exists(gitMetadata, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(gitMetadata)
                || (!Files.isDirectory(gitMetadata, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isRegularFile(gitMetadata, LinkOption.NOFOLLOW_LINKS))) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "project init requires non-symlink Git worktree metadata so only tracked files are copied");
        }
        if (gitAllowNoMatch(root, "config", "--local", "--name-only", "--get-regexp", "^filter\\.").length != 0) {
            throw Checks.conflict("template repositories with locally configured content filters are not allowed");
        }
        byte[] dirty = git(root, "status", "--porcelain", "--untracked-files=no");
        if (dirty.length != 0) {
            throw Checks.conflict("tracked template files are modified; commit or restore them before project init");
        }
        verifyVisibleIndexEntries(root);

        byte[] output = git(root, "ls-files", "--stage", "-z");
        List<Entry> result = new ArrayList<>();
        for (byte[] record : splitNul(output)) {
            String line = new String(record, StandardCharsets.UTF_8);
            int tab = line.indexOf('\t');
            if (tab <= 0) {
                throw Checks.conflict("unexpected git index record");
            }
            String[] metadata = line.substring(0, tab).split(" ");
            if (metadata.length != 3 || !"0".equals(metadata[2])) {
                throw Checks.conflict("template index contains an unresolved stage");
            }
            String mode = metadata[0];
            Path relative = Checks.safeRelative(Path.of(line.substring(tab + 1)));
            if (excluded(relative)) {
                continue;
            }
            if ("120000".equals(mode)) {
                throw Checks.conflict("tracked symlinks are not allowed in project templates: " + relative);
            }
            if (!("100644".equals(mode) || "100755".equals(mode))) {
                throw Checks.conflict("unsupported tracked template mode for " + relative);
            }
            Path source = root.resolve(relative).normalize();
            if (!source.startsWith(root) || !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(source)) {
                throw Checks.conflict("tracked template path is not a regular file: " + relative);
            }
            try (var channel = Files.newByteChannel(
                    source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                result.add(new Entry(
                        relative, Channels.newInputStream(channel).readAllBytes(), "100755".equals(mode)));
            }
            catch (IOException exception) {
                throw new ToolingException(ToolingException.IO_FAILURE, "unable to read template file " + relative, exception);
            }
        }
        if (result.isEmpty()) {
            throw Checks.conflict("tracked template tree is empty");
        }
        return List.copyOf(result);
    }

    private static void verifyVisibleIndexEntries(Path root) {
        for (byte[] record : splitNul(git(root, "ls-files", "-v", "-z"))) {
            if (record.length < 3 || record[0] != 'H' || record[1] != ' ') {
                throw Checks.conflict(
                        "template index contains assume-unchanged, skip-worktree, or non-cached entries");
            }
        }
    }

    static boolean excluded(Path relativePath) {
        String path = relativePath.toString().replace('\\', '/');
        String lower = path.toLowerCase(Locale.ROOT);
        String name = relativePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (EXCLUDED_DIRECTORIES.stream().anyMatch(directory -> withinDirectory(lower, directory))
                || lower.startsWith("release/evidence/") || lower.equals("release/evidence")) {
            return true;
        }
        if (name.equals(".env") || (name.startsWith(".env.") && !name.equals(".env.example"))) {
            return true;
        }
        if (SECRET_NAMES.contains(name) || SECRET_SUFFIXES.stream().anyMatch(name::endsWith)) {
            return true;
        }
        return DATED_ACCEPTANCE.matcher(path).matches();
    }

    private static boolean withinDirectory(String path, String directory) {
        return path.equals(directory) || path.startsWith(directory + "/")
                || path.contains("/" + directory + "/") || path.endsWith("/" + directory);
    }

    private static byte[] git(Path root, String... arguments) {
        return runGit(root, false, arguments);
    }

    private static byte[] gitAllowNoMatch(Path root, String... arguments) {
        return runGit(root, true, arguments);
    }

    private static byte[] runGit(Path root, boolean allowNoMatch, String... arguments) {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-c");
        command.add("core.fsmonitor=false");
        command.add("-c");
        command.add("core.untrackedCache=false");
        command.add("-C");
        command.add(root.toString());
        command.addAll(List.of(arguments));
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put("GIT_OPTIONAL_LOCKS", "0");
            Process process = builder.start();
            byte[] output = process.getInputStream().readAllBytes();
            int exit = process.waitFor();
            if (allowNoMatch && exit == 1) {
                return new byte[0];
            }
            if (exit != 0) {
                throw new ToolingException(ToolingException.PREREQUISITE,
                        "git could not read the tracked template tree");
            }
            return output;
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.PREREQUISITE, "git is required for project init", exception);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new ToolingException(ToolingException.PREREQUISITE, "git command was interrupted", exception);
        }
    }

    private static List<byte[]> splitNul(byte[] bytes) {
        List<byte[]> records = new ArrayList<>();
        int start = 0;
        for (int index = 0; index < bytes.length; index++) {
            if (bytes[index] == 0) {
                records.add(java.util.Arrays.copyOfRange(bytes, start, index));
                start = index + 1;
            }
        }
        if (start < bytes.length) {
            records.add(java.util.Arrays.copyOfRange(bytes, start, bytes.length));
        }
        return records;
    }
}
