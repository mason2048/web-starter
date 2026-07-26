package dev.webstarter.system.service;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuditSearchQueryTest {

    @Test
    void rejectsAnInvertedOccurrenceRange() {
        LocalDateTime earlier = LocalDateTime.of(2026, 7, 19, 10, 0);
        LocalDateTime later = earlier.plusMinutes(1);

        assertThrows(IllegalArgumentException.class, () -> query(later, earlier));
        assertDoesNotThrow(() -> query(earlier, later));
    }

    @Test
    void normalizesBoundedFiltersAndRejectsUnsafeTraceIdentifiers() {
        AuditSearchQuery normalized = new AuditSearchQuery(
                1, 20, " operator ", " SUCCESS ", " trace-safe-123 ",
                " project ", " project ", " 42 ", " project.create ", null, null);

        assertEquals("operator", normalized.subject());
        assertEquals("SUCCESS", normalized.result());
        assertEquals("trace-safe-123", normalized.traceId());
        assertEquals("42", normalized.resourceId());
        assertNull(new AuditSearchQuery(
                1, 20, "  ", null, null, null, null, null, null, null, null).subject());
        assertThrows(IllegalArgumentException.class, () -> new AuditSearchQuery(
                1, 20, null, null, "trace with spaces", null,
                null, null, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> new AuditSearchQuery(
                1, 20, "x".repeat(129), null, null, null,
                null, null, null, null, null));
    }

    private static AuditSearchQuery query(LocalDateTime from, LocalDateTime to) {
        return new AuditSearchQuery(1, 20, null, null, null, null,
                null, null, null, from, to);
    }
}
