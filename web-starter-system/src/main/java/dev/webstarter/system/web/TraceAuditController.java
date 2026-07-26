package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.system.dto.TraceAuditResponse;
import dev.webstarter.system.service.AuditQueryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/logs/trace")
public class TraceAuditController {

    private final AuditQueryService auditQueryService;

    public TraceAuditController(AuditQueryService auditQueryService) {
        this.auditQueryService = auditQueryService;
    }

    @GetMapping("/{traceId}")
    public ApiResponse<TraceAuditResponse> find(@PathVariable String traceId) {
        return ApiResponse.success(auditQueryService.findByTrace(traceId));
    }
}
