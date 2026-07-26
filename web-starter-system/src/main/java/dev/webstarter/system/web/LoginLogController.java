package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.LoginLogResponse;
import dev.webstarter.system.service.AuditSearchQuery;
import dev.webstarter.system.service.AuditQueryService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/logs/login")
public class LoginLogController {
    private final AuditQueryService auditQueryService;

    public LoginLogController(AuditQueryService auditQueryService) { this.auditQueryService = auditQueryService; }

    @GetMapping
    public ApiResponse<PageResult<LoginLogResponse>> page(@RequestParam(defaultValue = "1") long page,
                                                          @RequestParam(defaultValue = "20") long size,
                                                          @RequestParam(required = false) String username,
                                                          @RequestParam(required = false) String result,
                                                          @RequestParam(required = false) String traceId,
                                                          @RequestParam(required = false)
                                                          @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
                                                          LocalDateTime occurredFrom,
                                                          @RequestParam(required = false)
                                                          @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
                                                          LocalDateTime occurredTo) {
        return ApiResponse.success(auditQueryService.pageLogin(new AuditSearchQuery(
                page, size, username, result, traceId, null, null, null, null, occurredFrom, occurredTo)));
    }
}
