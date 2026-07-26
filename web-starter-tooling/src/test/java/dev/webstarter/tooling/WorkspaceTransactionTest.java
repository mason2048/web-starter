package dev.webstarter.tooling;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class WorkspaceTransactionTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void restoresOriginalBytesAndRemovesAdditionsWhenAWriteFails() throws Exception {
        Path existing = temporaryDirectory.resolve("existing.txt");
        Files.writeString(existing, "original");
        ChangePlan plan = new ChangePlan(temporaryDirectory);
        plan.modify(Path.of("existing.txt"), "changed");
        plan.add(Path.of("generated/first.txt"), "first");
        plan.add(Path.of("generated/second.txt"), "second");

        WorkspaceTransaction transaction = new WorkspaceTransaction((count, path) -> {
            if (count == 2) {
                throw new IOException("injected failure");
            }
        });

        assertThrows(ToolingException.class, () -> transaction.apply(plan));
        assertEquals("original", Files.readString(existing));
        assertFalse(Files.exists(temporaryDirectory.resolve("generated/first.txt")));
        assertFalse(Files.exists(temporaryDirectory.resolve("generated/second.txt")));
        assertFalse(Files.exists(temporaryDirectory.resolve("generated")));
    }

    @Test
    void preconditionChangeStopsBeforeAnyWrite() throws Exception {
        Path existing = temporaryDirectory.resolve("existing.txt");
        Files.writeString(existing, "before");
        ChangePlan plan = new ChangePlan(temporaryDirectory);
        plan.modify(Path.of("existing.txt"), "after");
        plan.add(Path.of("new.txt"), "new");
        Files.writeString(existing, "concurrent-change");

        ToolingException failure = assertThrows(ToolingException.class,
                () -> new WorkspaceTransaction().apply(plan));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertEquals("concurrent-change", Files.readString(existing));
        assertFalse(Files.exists(temporaryDirectory.resolve("new.txt")));
    }

    @Test
    void successfulModifyPreservesRestrictivePosixPermissions() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path existing = temporaryDirectory.resolve("restricted.txt");
        Files.writeString(existing, "before");
        Set<PosixFilePermission> restrictive = Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(existing, restrictive);
        ChangePlan plan = new ChangePlan(temporaryDirectory);
        plan.modify(Path.of("restricted.txt"), "after");

        new WorkspaceTransaction().apply(plan);

        assertEquals("after", Files.readString(existing));
        assertEquals(restrictive, Files.getPosixFilePermissions(existing));
    }

    @Test
    void rollbackRestoresOriginalPosixPermissionsAfterInjectedFailure() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path existing = temporaryDirectory.resolve("restricted.txt");
        Files.writeString(existing, "before");
        Set<PosixFilePermission> restrictive = Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(existing, restrictive);
        ChangePlan plan = new ChangePlan(temporaryDirectory);
        plan.modify(Path.of("restricted.txt"), "after");
        WorkspaceTransaction transaction = new WorkspaceTransaction((count, path) -> {
            Files.setPosixFilePermissions(existing, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ));
            throw new IOException("injected failure after permission change");
        });

        assertThrows(ToolingException.class, () -> transaction.apply(plan));

        assertEquals("before", Files.readString(existing));
        assertEquals(restrictive, Files.getPosixFilePermissions(existing));
    }

    @Test
    void refusesAnAddWhoseParentIsASymbolicLink() throws Exception {
        Path outside = Files.createDirectory(temporaryDirectory.resolveSibling(
                temporaryDirectory.getFileName() + "-outside"));
        try {
            Files.createSymbolicLink(temporaryDirectory.resolve("generated"), outside);
            ChangePlan plan = new ChangePlan(temporaryDirectory);
            plan.add(Path.of("generated/file.txt"), "must-not-escape");

            ToolingException failure = assertThrows(
                    ToolingException.class, () -> new WorkspaceTransaction().apply(plan));

            assertEquals(ToolingException.CONFLICT, failure.exitCode());
            assertFalse(Files.exists(outside.resolve("file.txt")));
        }
        finally {
            Files.deleteIfExists(outside);
        }
    }

    @Test
    void planDigestBindsExecutableModeAndOriginalModifyContent() throws Exception {
        ChangePlan regular = new ChangePlan(temporaryDirectory);
        regular.add(Path.of("script.sh"), "same".getBytes(java.nio.charset.StandardCharsets.UTF_8), false);
        ChangePlan executable = new ChangePlan(temporaryDirectory);
        executable.add(Path.of("script.sh"), "same".getBytes(java.nio.charset.StandardCharsets.UTF_8), true);

        assertFalse(regular.digest().equals(executable.digest()));

        Path firstRoot = Files.createDirectory(temporaryDirectory.resolve("first"));
        Path secondRoot = Files.createDirectory(temporaryDirectory.resolve("second"));
        Files.writeString(firstRoot.resolve("existing.txt"), "first baseline");
        Files.writeString(secondRoot.resolve("existing.txt"), "second baseline");
        ChangePlan first = new ChangePlan(firstRoot);
        first.modify(Path.of("existing.txt"), "same result");
        ChangePlan second = new ChangePlan(secondRoot);
        second.modify(Path.of("existing.txt"), "same result");

        assertFalse(first.digest().equals(second.digest()));
    }

    @Test
    void reportsRollbackFailureWithoutClaimingAtomicRestoration() throws Exception {
        Path existing = temporaryDirectory.resolve("existing.txt");
        Files.writeString(existing, "before");
        ChangePlan plan = new ChangePlan(temporaryDirectory);
        plan.modify(Path.of("existing.txt"), "after");
        WorkspaceTransaction transaction = new WorkspaceTransaction((count, path) -> {
            Files.delete(existing);
            throw new IOException("injected failure after concurrent deletion");
        });

        ToolingException failure = assertThrows(ToolingException.class, () -> transaction.apply(plan));

        assertEquals(ToolingException.IO_FAILURE, failure.exitCode());
        assertEquals("workspace transaction failed and rollback was incomplete", failure.getMessage());
        assertFalse(Files.exists(existing));
    }
}
