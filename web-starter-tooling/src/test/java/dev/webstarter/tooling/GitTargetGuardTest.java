package dev.webstarter.tooling;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GitTargetGuardTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void refusesLocalContentFiltersBeforeStatusCanExecuteThem() throws Exception {
        Path target = temporaryDirectory.resolve("existing.txt");
        Files.writeString(target, "original\n");
        Files.writeString(temporaryDirectory.resolve(".gitattributes"), "existing.txt filter=probe\n");
        git("init", "-q");
        git("config", "user.email", "tooling-test@example.invalid");
        git("config", "user.name", "Tooling Test");
        git("add", ".gitattributes", "existing.txt");
        git("commit", "-q", "-m", "fixture");

        Path marker = temporaryDirectory.resolve("filter-was-executed");
        Path filter = temporaryDirectory.resolve(".git/hooks/filter-probe");
        Files.writeString(filter, "#!/bin/sh\n: > \"" + marker + "\"\ncat\n");
        filter.toFile().setExecutable(true, true);
        git("config", "filter.probe.clean", filter.toString());
        Files.setLastModifiedTime(target, FileTime.from(Instant.now().plusSeconds(2)));
        ChangePlan plan = new ChangePlan(temporaryDirectory);
        plan.modify(Path.of("existing.txt"), "updated\n");

        ToolingException failure = assertThrows(ToolingException.class, () -> GitTargetGuard.verify(plan));

        assertEquals(ToolingException.CONFLICT, failure.exitCode());
        assertFalse(Files.exists(marker));
        assertEquals("original\n", Files.readString(target));
    }

    private void git(String... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-C");
        command.add(temporaryDirectory.toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] output = process.getInputStream().readAllBytes();
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IOException("git fixture command failed: " + new String(output));
        }
    }
}
