package dev.webstarter.system.service;

import java.time.LocalDateTime;

/**
 * Shared, transport-neutral audit search criteria.
 *
 * <p>Only the fields relevant to a log type are applied. Keeping the criteria
 * in the application layer lets REST and future adapters share the same
 * permission and validation boundary.</p>
 */
public record AuditSearchQuery(
        long page,
        long size,
        String subject,
        String result,
        String traceId,
        String module,
        String resourceType,
        String resourceId,
        String toolName,
        LocalDateTime occurredFrom,
        LocalDateTime occurredTo) {

    public AuditSearchQuery {
        subject = normalize(subject, 128, "subject");
        result = normalize(result, 20, "result");
        traceId = normalize(traceId, 64, "traceId");
        module = normalize(module, 64, "module");
        resourceType = normalize(resourceType, 64, "resourceType");
        resourceId = normalize(resourceId, 128, "resourceId");
        toolName = normalize(toolName, 128, "toolName");
        if (traceId != null && !traceId.matches("[A-Za-z0-9._-]{8,64}")) {
            throw new IllegalArgumentException("traceId has an invalid format");
        }
        if (occurredFrom != null && occurredTo != null && occurredFrom.isAfter(occurredTo)) {
            throw new IllegalArgumentException("occurredFrom must not be after occurredTo");
        }
    }

    private static String normalize(String value, int maximumLength, String name) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > maximumLength) {
            throw new IllegalArgumentException(name + " is too long");
        }
        return normalized;
    }
}
