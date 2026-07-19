package dev.webstarter.core.api;

import dev.webstarter.core.trace.TraceContext;

public record ApiResponse<T>(int code, String message, T data, String traceId) {

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(ApiCodes.SUCCESS, "OK", data, TraceContext.traceId());
    }

    public static ApiResponse<Void> success() {
        return success(null);
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        return new ApiResponse<>(code, message, null, TraceContext.traceId());
    }
}
