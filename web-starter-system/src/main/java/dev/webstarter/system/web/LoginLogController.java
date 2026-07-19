package dev.webstarter.system.web;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.api.PageResult;
import dev.webstarter.system.dto.LoginLogResponse;
import dev.webstarter.system.service.AuditQueryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/logs/login")
public class LoginLogController {
    private final AuditQueryService auditQueryService;

    public LoginLogController(AuditQueryService auditQueryService) { this.auditQueryService = auditQueryService; }

    @GetMapping
    public ApiResponse<PageResult<LoginLogResponse>> page(@RequestParam(defaultValue = "1") long page,
                                                          @RequestParam(defaultValue = "20") long size,
                                                          @RequestParam(required = false) String username,
                                                          @RequestParam(required = false) String result) {
        return ApiResponse.success(auditQueryService.pageLogin(page, size, username, result));
    }
}
