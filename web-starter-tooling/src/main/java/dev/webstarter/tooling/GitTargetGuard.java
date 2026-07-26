package dev.webstarter.tooling;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Refuses to rewrite tracked files that already contain user changes. */
public final class GitTargetGuard {

    private GitTargetGuard() {
    }

    public static void verify(ChangePlan plan) {
        Path gitMetadata = plan.root().resolve(".git");
        if (!Files.exists(gitMetadata, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (Files.isSymbolicLink(gitMetadata)
                || (!Files.isDirectory(gitMetadata, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isRegularFile(gitMetadata, LinkOption.NOFOLLOW_LINKS))) {
            throw Checks.conflict("workspace Git metadata must be a non-symlink file or directory");
        }
        if (hasLocalContentFilters(plan.root())) {
            throw Checks.conflict("workspace repositories with locally configured content filters are not allowed");
        }
        List<String> modifiedTargets = plan.changes().stream()
                .filter(change -> change.kind() == ChangePlan.Kind.MODIFY)
                .map(change -> change.relativePath().toString())
                .toList();
        if (modifiedTargets.isEmpty()) {
            return;
        }
        List<String> command = gitCommand(plan.root());
        command.add("status");
        command.add("--porcelain");
        command.add("--untracked-files=no");
        command.add("--");
        command.addAll(modifiedTargets);
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put("GIT_OPTIONAL_LOCKS", "0");
            Process process = builder.start();
            byte[] output = process.getInputStream().readAllBytes();
            int exit = process.waitFor();
            if (exit != 0) {
                throw new ToolingException(ToolingException.PREREQUISITE,
                        "git could not inspect planned target files");
            }
            if (output.length > 0) {
                throw Checks.conflict("one or more planned existing files have uncommitted changes");
            }
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "git is required to protect modified target files", exception);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "git target inspection was interrupted", exception);
        }
    }

    private static boolean hasLocalContentFilters(Path root) {
        List<String> command = gitCommand(root);
        command.add("config");
        command.add("--local");
        command.add("--name-only");
        command.add("--get-regexp");
        command.add("^filter\\.");
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put("GIT_OPTIONAL_LOCKS", "0");
            Process process = builder.start();
            byte[] output = process.getInputStream().readAllBytes();
            int exit = process.waitFor();
            if (exit == 1) {
                return false;
            }
            if (exit != 0) {
                throw new ToolingException(ToolingException.PREREQUISITE,
                        "git could not inspect workspace content filters");
            }
            return output.length > 0;
        }
        catch (IOException exception) {
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "git is required to protect modified target files", exception);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new ToolingException(ToolingException.PREREQUISITE,
                    "git target inspection was interrupted", exception);
        }
    }

    private static List<String> gitCommand(Path root) {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-c");
        command.add("core.fsmonitor=false");
        command.add("-c");
        command.add("core.untrackedCache=false");
        command.add("-C");
        command.add(root.toString());
        return command;
    }
}
