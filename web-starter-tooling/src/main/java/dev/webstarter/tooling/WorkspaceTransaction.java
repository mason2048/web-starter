package dev.webstarter.tooling;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Applies a preconditioned plan using sibling atomic moves and exact rollback. */
public final class WorkspaceTransaction {

    @FunctionalInterface
    interface WriteObserver {
        void afterWrite(int completedWrites, Path relativePath) throws IOException;
    }

    private final WriteObserver observer;

    public WorkspaceTransaction() {
        this((count, path) -> { });
    }

    WorkspaceTransaction(WriteObserver observer) {
        this.observer = observer;
    }

    public void apply(ChangePlan plan) {
        plan.preflight();
        Path backupDirectory = null;
        Map<Path, Path> backups = new HashMap<>();
        List<Path> written = new ArrayList<>();
        List<Path> createdDirectories = new ArrayList<>();
        try {
            backupDirectory = Files.createTempDirectory("web-starter-transaction-");
            int backupIndex = 0;
            for (ChangePlan.Change change : plan.changes()) {
                Path target = plan.resolve(change.relativePath());
                if (change.kind() == ChangePlan.Kind.MODIFY) {
                    Path backup = backupDirectory.resolve(String.format("%05d.backup", backupIndex++));
                    Files.copy(target, backup, StandardCopyOption.COPY_ATTRIBUTES);
                    verifyExpectedContent(backup, change);
                    backups.put(change.relativePath(), backup);
                }
            }

            int completed = 0;
            for (ChangePlan.Change change : plan.changes()) {
                Path target = plan.resolve(change.relativePath());
                createParents(plan.root(), target.getParent(), createdDirectories);
                if (change.kind() == ChangePlan.Kind.MODIFY) {
                    verifyExpectedContent(target, change);
                }
                atomicWrite(target, change.content(), change.kind() == ChangePlan.Kind.MODIFY, change.executable());
                written.add(change.relativePath());
                observer.afterWrite(++completed, change.relativePath());
            }
        }
        catch (Exception failure) {
            IOException rollbackFailure = rollback(plan, written, backups, createdDirectories);
            if (rollbackFailure != null) {
                failure.addSuppressed(rollbackFailure);
                throw new ToolingException(ToolingException.IO_FAILURE,
                        "workspace transaction failed and rollback was incomplete", failure);
            }
            if (failure instanceof ToolingException toolingException) {
                throw toolingException;
            }
            throw new ToolingException(ToolingException.IO_FAILURE,
                    "workspace transaction failed and was rolled back", failure);
        }
        finally {
            deleteTreeQuietly(backupDirectory);
        }
    }

    private static void verifyExpectedContent(Path path, ChangePlan.Change change) throws IOException {
        String actual = Digests.sha256(Files.readAllBytes(path));
        if (!actual.equals(change.expectedSha256())) {
            throw Checks.conflict("planned file changed during transaction: " + change.relativePath());
        }
    }

    private static void atomicWrite(Path target, byte[] content, boolean replace, boolean executable) throws IOException {
        Path temporary = target.resolveSibling("." + target.getFileName() + ".web-starter-" + UUID.randomUUID());
        Set<PosixFilePermission> existingPermissions = replace ? posixPermissions(target) : null;
        try {
            Files.write(temporary, content);
            if (existingPermissions == null) {
                setExecutable(temporary, executable);
            }
            else {
                Files.setPosixFilePermissions(temporary, existingPermissions);
            }
            if (replace) {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            }
            else {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            }
        }
        catch (AtomicMoveNotSupportedException exception) {
            throw new IOException("atomic file replacement is not supported for " + target, exception);
        }
        finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static Set<PosixFilePermission> posixPermissions(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = EnumSet.noneOf(PosixFilePermission.class);
            permissions.addAll(Files.getPosixFilePermissions(path));
            return permissions;
        }
        catch (UnsupportedOperationException ignored) {
            return null;
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
            // Windows preserves launchability through the .cmd wrapper.
        }
    }

    private static void createParents(Path root, Path directory, List<Path> created) throws IOException {
        if (directory == null || directory.equals(root) || Files.exists(directory)) {
            return;
        }
        createParents(root, directory.getParent(), created);
        try {
            Files.createDirectory(directory);
            created.add(directory);
        }
        catch (FileAlreadyExistsException ignored) {
            if (!Files.isDirectory(directory) || Files.isSymbolicLink(directory)) {
                throw ignored;
            }
        }
    }

    private static IOException rollback(
            ChangePlan plan,
            List<Path> written,
            Map<Path, Path> backups,
            List<Path> createdDirectories) {
        IOException result = null;
        for (int index = written.size() - 1; index >= 0; index--) {
            Path relative = written.get(index);
            Path target = plan.resolve(relative);
            try {
                Path backup = backups.get(relative);
                if (backup == null) {
                    Files.deleteIfExists(target);
                }
                else {
                    atomicWrite(target, Files.readAllBytes(backup), true, Files.isExecutable(backup));
                    restorePosixPermissions(backup, target);
                }
            }
            catch (IOException exception) {
                if (result == null) {
                    result = exception;
                }
                else {
                    result.addSuppressed(exception);
                }
            }
        }
        createdDirectories.stream()
                .sorted(Comparator.comparingInt(Path::getNameCount).reversed())
                .forEach(directory -> {
                    try {
                        Files.deleteIfExists(directory);
                    }
                    catch (IOException ignored) {
                        // A concurrent file makes the directory non-empty; never remove it recursively.
                    }
                });
        return result;
    }

    private static void restorePosixPermissions(Path source, Path target) throws IOException {
        Set<PosixFilePermission> permissions = posixPermissions(source);
        if (permissions != null) {
            Files.setPosixFilePermissions(target, permissions);
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
                    // Temporary backups contain no user-owned files; JVM exit cleanup is sufficient fallback.
                }
            });
        }
        catch (IOException ignored) {
            // See per-path cleanup note above.
        }
    }
}
