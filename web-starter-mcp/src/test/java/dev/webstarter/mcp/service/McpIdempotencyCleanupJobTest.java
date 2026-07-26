package dev.webstarter.mcp.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import dev.webstarter.mcp.persistence.mapper.McpIdempotencyMapper;

class McpIdempotencyCleanupJobTest {

    @Test
    void deletesCommittedBatchesUntilTheFirstPartialBatch() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        when(mapper.deleteExpiredBatch(any(), eq(500))).thenReturn(500, 500, 17);

        new McpIdempotencyCleanupJob(mapper).deleteExpired();

        verify(mapper, times(3)).deleteExpiredBatch(any(), eq(500));
    }

    @Test
    void capsEachScheduledRunToAvoidAnUnboundedCleanupLoop() {
        McpIdempotencyMapper mapper = mock(McpIdempotencyMapper.class);
        when(mapper.deleteExpiredBatch(any(), eq(500))).thenReturn(500);

        new McpIdempotencyCleanupJob(mapper).deleteExpired();

        verify(mapper, times(20)).deleteExpiredBatch(any(), eq(500));
    }
}
