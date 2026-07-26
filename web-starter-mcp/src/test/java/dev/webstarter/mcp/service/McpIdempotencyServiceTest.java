package dev.webstarter.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import io.modelcontextprotocol.json.McpJsonDefaults;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.mcp.config.McpIdempotencyProperties;
import dev.webstarter.mcp.persistence.mapper.McpIdempotencyMapper;
import dev.webstarter.mcp.persistence.model.McpIdempotencyRecord;

class McpIdempotencyServiceTest {

    private static final String KEY = "retry-key-00000001";

    @AfterEach
    void clearInvocationMetadata() {
        McpInvocationMetadata.reset();
    }

    @Test
    void requiresTheSharedInvocationTransaction() throws Exception {
        var method = McpIdempotencyService.class.getMethod(
                "execute", String.class, Map.class, String.class, Supplier.class);
        var transaction = new AnnotationTransactionAttributeSource()
                .getTransactionAttribute(method, McpIdempotencyService.class);

        assertThat(transaction).isNotNull();
        assertThat(transaction.getPropagationBehavior())
                .isEqualTo(TransactionDefinition.PROPAGATION_MANDATORY);
    }

    @Test
    void executesNormallyWhenTheOptionalKeyIsAbsent() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        CallerContext callerContext = mock(CallerContext.class);
        McpIdempotencyService service = service(mapper, callerContext);

        String result = service.execute("project.create", Map.of("name", "Example"), null, () -> "created");

        assertThat(result).isEqualTo("created");
        verifyNoInteractions(mapper, callerContext);
    }

    @Test
    void storesOnlyHashesAndReplaysTheCompletedResponseWithoutRepeatingTheWrite() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.required()).thenReturn(caller());
        AtomicReference<McpIdempotencyRecord> stored = new AtomicReference<>();
        when(mapper.claim(any())).thenAnswer(invocation -> {
            McpIdempotencyRecord candidate = invocation.getArgument(0);
            if (stored.compareAndSet(null, candidate)) {
                return 1;
            }
            return 0;
        });
        when(mapper.complete(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(invocation -> {
                    McpIdempotencyRecord record = stored.get();
                    record.setStatus("COMPLETED");
                    record.setResponseJson(invocation.getArgument(4));
                    record.setResourceId(invocation.getArgument(5));
                    record.setCompletedAt(invocation.getArgument(6));
                    return 1;
                });
        when(mapper.findForUpdate(anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> stored.get());
        McpIdempotencyService service = service(mapper, callerContext);
        AtomicInteger writes = new AtomicInteger();
        Map<String, Object> arguments = Map.of(
                "name", "Example",
                McpIdempotencyService.ARGUMENT_NAME, KEY);

        Map<String, Object> first = service.execute("project.create", arguments, KEY, () -> {
            writes.incrementAndGet();
            return Map.of("id", 42L, "name", "Example");
        });
        Object second = service.execute("project.create", arguments, KEY, () -> {
            writes.incrementAndGet();
            return Map.of("id", 99L);
        });

        assertThat(first).containsEntry("id", 42L);
        assertThat(second).isInstanceOfSatisfying(Map.class, replay ->
                assertThat(replay).containsEntry("id", 42));
        assertThat(writes).hasValue(1);
        assertThat(stored.get().getIdempotencyKeyHash())
                .hasSize(64)
                .doesNotContain(KEY);
        assertThat(stored.get().getNamespaceHash()).hasSize(64);
        assertThat(stored.get().getRequestHash()).hasSize(64);
        assertThat(stored.get().getResourceId()).isEqualTo("42");
        assertThat(McpInvocationMetadata.keyHash()).isEqualTo(stored.get().getIdempotencyKeyHash());
        assertThat(McpInvocationMetadata.replayed()).isTrue();
        verify(mapper).complete(
                eq(stored.get().getNamespaceHash()),
                eq("project.create"),
                eq(stored.get().getIdempotencyKeyHash()),
                eq(stored.get().getReservationNonce()),
                anyString(),
                eq("42"),
                any(LocalDateTime.class),
                any(LocalDateTime.class));
    }

    @Test
    void rejectsReuseOfTheSameKeyWithDifferentArguments() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.required()).thenReturn(caller());
        AtomicReference<McpIdempotencyRecord> stored = new AtomicReference<>();
        when(mapper.claim(any())).thenAnswer(invocation -> {
            McpIdempotencyRecord candidate = invocation.getArgument(0);
            if (stored.compareAndSet(null, candidate)) {
                return 1;
            }
            return 0;
        });
        when(mapper.complete(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenAnswer(invocation -> {
                    McpIdempotencyRecord record = stored.get();
                    record.setStatus("COMPLETED");
                    record.setResponseJson(invocation.getArgument(4));
                    return 1;
                });
        when(mapper.findForUpdate(anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> stored.get());
        McpIdempotencyService service = service(mapper, callerContext);

        service.execute("project.create", Map.of("name", "First"), KEY, () -> Map.of("id", 1L));

        assertThatThrownBy(() -> service.execute(
                "project.create", Map.of("name", "Different"), KEY, () -> Map.of("id", 2L)))
                .isInstanceOf(McpIdempotencyConflictException.class)
                .hasMessageContaining("different arguments");
    }

    @Test
    void rejectsAnInvalidKeyBeforeAccessingPersistenceOrExecutingTheWrite() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        CallerContext callerContext = mock(CallerContext.class);
        McpIdempotencyService service = service(mapper, callerContext);
        AtomicInteger writes = new AtomicInteger();

        assertThatThrownBy(() -> service.execute(
                "project.create", Map.of(), "short", () -> writes.incrementAndGet()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("16-128");

        assertThat(writes).hasValue(0);
        verifyNoInteractions(mapper, callerContext);
        verify(mapper, never()).claim(any());
    }

    @Test
    void atomicallyTakesOwnershipOfAnExpiredReservation() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        CallerContext callerContext = mock(CallerContext.class);
        when(callerContext.required()).thenReturn(caller());
        McpIdempotencyRecord expired = new McpIdempotencyRecord();
        expired.setReservationNonce("expired-reservation-nonce-000001");
        expired.setExpiresAt(LocalDateTime.now().minusMinutes(1));
        AtomicReference<McpIdempotencyRecord> stored = new AtomicReference<>(expired);
        when(mapper.claim(any())).thenAnswer(invocation -> {
            McpIdempotencyRecord candidate = invocation.getArgument(0);
            McpIdempotencyRecord current = stored.get();
            current.setNamespaceHash(candidate.getNamespaceHash());
            current.setToolName(candidate.getToolName());
            current.setIdempotencyKeyHash(candidate.getIdempotencyKeyHash());
            current.setReservationNonce(candidate.getReservationNonce());
            current.setRequestHash(candidate.getRequestHash());
            current.setStatus(candidate.getStatus());
            current.setCreatedAt(candidate.getCreatedAt());
            current.setExpiresAt(candidate.getExpiresAt());
            return 2;
        });
        when(mapper.findForUpdate(anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> stored.get());
        when(mapper.complete(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(1);
        McpIdempotencyService service = service(mapper, callerContext);

        Map<String, Object> result = service.execute(
                "project.create", Map.of("name", "Replacement"), KEY, () -> Map.of("id", 77L));

        assertThat(result).containsEntry("id", 77L);
        verify(mapper).claim(any());
        assertThat(stored.get().getReservationNonce())
                .hasSize(32)
                .isNotEqualTo("expired-reservation-nonce-000001");
    }

    private static McpIdempotencyService service(McpIdempotencyMapper mapper, CallerContext callerContext) {
        return new McpIdempotencyService(
                mapper,
                callerContext,
                McpJsonDefaults.getMapper(),
                new McpIdempotencyProperties(Duration.ofHours(24), Duration.ofMinutes(10)));
    }

    private static CurrentCaller caller() {
        return new CurrentCaller(
                CallerType.USER,
                "7",
                "operator",
                "Operator",
                "pat-17",
                "agent-client",
                Set.of("project:create"),
                Set.of("project:create"),
                Set.of(),
                "trace-1");
    }
}
