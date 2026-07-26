package dev.webstarter.mcp.service;

final class McpIdempotencyConflictException extends RuntimeException {

    McpIdempotencyConflictException(String message) {
        super(message);
    }
}
