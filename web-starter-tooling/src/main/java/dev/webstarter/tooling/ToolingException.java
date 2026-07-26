package dev.webstarter.tooling;

/** A user-actionable tooling failure with a stable process exit code. */
public final class ToolingException extends RuntimeException {

    public static final int USAGE = 2;
    public static final int PREREQUISITE = 3;
    public static final int CONFLICT = 4;
    public static final int IO_FAILURE = 5;

    private final int exitCode;

    public ToolingException(int exitCode, String message) {
        super(message);
        this.exitCode = exitCode;
    }

    public ToolingException(int exitCode, String message, Throwable cause) {
        super(message, cause);
        this.exitCode = exitCode;
    }

    public int exitCode() {
        return exitCode;
    }
}
