package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.McpCallLogResponse;
import dev.webstarter.system.service.AuditQueryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/logs/mcp")
public class McpCallLogController {
    private final AuditQueryService auditQueryService;

    public McpCallLogController(AuditQueryService auditQueryService) { this.auditQueryService = auditQueryService; }

    @GetMapping
    public ApiResponse<PageResult<McpCallLogResponse>> page(@RequestParam(defaultValue = "1") long page,
                                                            @RequestParam(defaultValue = "20") long size,
                                                            @RequestParam(required = false) String actorName,
                                                            @RequestParam(required = false) String toolName,
                                                            @RequestParam(required = false) String result) {
        return ApiResponse.success(auditQueryService.pageMcp(page, size, actorName, toolName, result));
    }
}
