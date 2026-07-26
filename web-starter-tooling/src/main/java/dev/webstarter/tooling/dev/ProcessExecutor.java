package dev.webstarter.tooling.dev;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Executes a fixed argument vector without involving a command shell. */
@FunctionalInterface
public interface ProcessExecutor {

    String ENVIRONMENT_REMOVALS = "__WEB_STARTER_TOOLING_UNSET_ENV";

    Execution execute(List<String> command, Path workingDirectory,
            Map<String, String> environment, OutputStream output);

    record Execution(int exitCode) {
    }

    static ProcessExecutor system() {
        return (command, workingDirectory, environment, output) -> {
            Process process = null;
            try {
                Map<String, String> additions = new LinkedHashMap<>(environment);
                String removalList = additions.remove(ENVIRONMENT_REMOVALS);
                ProcessBuilder builder = new ProcessBuilder(command)
                        .directory(workingDirectory.toFile())
                        .redirectErrorStream(true);
                builder.environment().putAll(additions);
                if (removalList != null && !removalList.isBlank()) {
                    for (String name : removalList.split(",", -1)) {
                        if (!name.matches("[A-Za-z_][A-Za-z0-9_]*")) {
                            writeFailure(output, "invalid internal environment removal request");
                            return new Execution(127);
                        }
                        builder.environment().remove(name);
                    }
                }
                process = builder.start();
                process.getInputStream().transferTo(output);
                return new Execution(process.waitFor());
            }
            catch (IOException exception) {
                writeFailure(output, "unable to start " + displayName(command));
                return new Execution(127);
            }
            catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                if (process != null) {
                    process.destroyForcibly();
                }
                writeFailure(output, "command interrupted: " + displayName(command));
                return new Execution(130);
            }
        };
    }

    private static String displayName(List<String> command) {
        if (command.isEmpty()) {
            return "command";
        }
        Path executable = Path.of(command.getFirst());
        Path fileName = executable.getFileName();
        return fileName == null ? "command" : fileName.toString();
    }

    private static void writeFailure(OutputStream output, String message) {
        try {
            output.write((message + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
        }
        catch (IOException ignored) {
            // The command exit code still reports the failure when its diagnostic sink is unavailable.
        }
    }
}
