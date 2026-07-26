package dev.webstarter.mcp.service;

final class McpIdempotencyInProgressException extends RuntimeException {

    McpIdempotencyInProgressException() {
        super("The idempotent request is still being processed");
    }
}
