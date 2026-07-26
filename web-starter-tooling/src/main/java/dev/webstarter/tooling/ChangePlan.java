package dev.webstarter.tooling;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Immutable-intent file changes built and conflict-checked before any write. */
public final class ChangePlan {

    public enum Kind { ADD, MODIFY }

    public record Change(Path relativePath, Kind kind, String expectedSha256, byte[] content, boolean executable) {
        public Change {
            relativePath = Checks.safeRelative(relativePath);
            content = content.clone();
        }

        @Override
        public byte[] content() {
            return content.clone();
        }
    }

    private final Path root;
    private final Map<Path, Change> changes = new LinkedHashMap<>();

    public ChangePlan(Path root) {
        this.root = Checks.existingDirectory(root, "workspace");
    }

    public Path root() {
        return root;
    }

    public void add(Path relativePath, String content) {
        add(relativePath, content.getBytes(StandardCharsets.UTF_8), false);
    }

    public void add(Path relativePath, byte[] content, boolean executable) {
        Path safe = Checks.safeRelative(relativePath);
        Path target = resolve(safe);
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw Checks.conflict("target already exists: " + safe);
        }
        put(new Change(safe, Kind.ADD, null, content, executable));
    }

    public void modify(Path relativePath, String content) {
        modify(relativePath, content.getBytes(StandardCharsets.UTF_8));
    }

    public void modify(Path relativePath, byte[] content) {
        Path safe = Checks.safeRelative(relativePath);
        Path target = resolve(safe);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(target)) {
            throw Checks.conflict("required regular file is missing: " + safe);
        }
        try {
            byte[] existing = Files.readAllBytes(target);
            put(new Change(safe, Kind.MODIFY, Digests.sha256(existing), content, Files.isExecutable(target)));
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.IO_FAILURE, "unable to read " + safe, exception);
        }
    }

    public List<Change> changes() {
        return changes.values().stream()
                .sorted(Comparator.comparing(change -> change.relativePath().toString()))
                .toList();
    }

    public String digest() {
        List<byte[]> parts = new ArrayList<>();
        int length = 0;
        for (Change change : changes()) {
            byte[] part = (change.kind() + "\0" + change.relativePath() + "\0"
                    + (change.expectedSha256() == null ? "-" : change.expectedSha256()) + "\0"
                    + Digests.sha256(change.content()) + "\0"
                    + (change.executable() ? "100755" : "100644") + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            parts.add(part);
            length += part.length;
        }
        byte[] joined = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, joined, offset, part.length);
            offset += part.length;
        }
        return Digests.sha256(joined);
    }

    public void preflight() {
        for (Change change : changes()) {
            Path target = resolve(change.relativePath());
            verifyParents(target.getParent());
            if (change.kind() == Kind.ADD) {
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw Checks.conflict("target appeared after planning: " + change.relativePath());
                }
            }
            else {
                if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(target)) {
                    throw Checks.conflict("planned file changed type: " + change.relativePath());
                }
                try {
                    String actual = Digests.sha256(Files.readAllBytes(target));
                    if (!actual.equals(change.expectedSha256())) {
                        throw Checks.conflict("planned file changed after planning: " + change.relativePath());
                    }
                }
                catch (IOException exception) {
                    throw new ToolingException(ToolingException.IO_FAILURE,
                            "unable to re-read " + change.relativePath(), exception);
                }
            }
        }
    }

    Path resolve(Path relativePath) {
        Path target = root.resolve(relativePath).normalize();
        if (!target.startsWith(root)) {
            throw Checks.usage("path escapes workspace: " + relativePath);
        }
        return target;
    }

    private void verifyParents(Path directory) {
        Path cursor = directory;
        while (cursor != null && cursor.startsWith(root) && !cursor.equals(root)) {
            if (Files.exists(cursor, LinkOption.NOFOLLOW_LINKS) &&
                    (!Files.isDirectory(cursor, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(cursor))) {
                throw Checks.conflict("path contains a non-directory or symlink: " + root.relativize(cursor));
            }
            cursor = cursor.getParent();
        }
    }

    private void put(Change change) {
        if (changes.putIfAbsent(change.relativePath(), change) != null) {
            throw Checks.conflict("duplicate planned path: " + change.relativePath());
        }
    }
}
