package dev.webstarter.core.trace;

import org.slf4j.MDC;

import java.util.UUID;

public final class TraceContext {

    public static final String TRACE_ID_KEY = "traceId";

    private TraceContext() {
    }

    public static String traceId() {
        String current = MDC.get(TRACE_ID_KEY);
        if (current != null && !current.isBlank()) {
            return current;
        }
        String generated = UUID.randomUUID().toString().replace("-", "");
        MDC.put(TRACE_ID_KEY, generated);
        return generated;
    }
}
