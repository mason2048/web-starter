package dev.webstarter.mcp.service;

import java.time.LocalDateTime;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import dev.webstarter.mcp.persistence.mapper.McpIdempotencyMapper;

@Component
public class McpIdempotencyCleanupJob {

    private static final int BATCH_SIZE = 500;
    private static final int MAX_BATCHES_PER_RUN = 20;

    private final McpIdempotencyMapper mapper;

    public McpIdempotencyCleanupJob(McpIdempotencyMapper mapper) {
        this.mapper = mapper;
    }

    @Scheduled(fixedDelayString = "${web-starter.mcp.idempotency.cleanup-interval:PT10M}")
    public void deleteExpired() {
        for (int batch = 0; batch < MAX_BATCHES_PER_RUN; batch++) {
            int deleted = mapper.deleteExpiredBatch(LocalDateTime.now(), BATCH_SIZE);
            if (deleted < BATCH_SIZE) {
                return;
            }
        }
    }
}
