package dev.webstarter.security.web;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.security.token.AccessCredentialService;
import dev.webstarter.security.token.CredentialType;
import dev.webstarter.security.web.SecurityManagementDtos.IssueTokenRequest;
import dev.webstarter.security.web.SecurityManagementDtos.IssuedTokenResponse;
import dev.webstarter.security.web.SecurityManagementDtos.TokenSummary;

@RestController
@RequestMapping("/api/security/personal-tokens")
public class PersonalTokenController {

    private final AccessCredentialService credentialService;
    private final CallerContext callerContext;
    private final PermissionService permissionService;

    public PersonalTokenController(
            AccessCredentialService credentialService,
            CallerContext callerContext,
            PermissionService permissionService) {
        this.credentialService = credentialService;
        this.callerContext = callerContext;
        this.permissionService = permissionService;
    }

    @PostMapping
    public ApiResponse<IssuedTokenResponse> issue(@Valid @RequestBody IssueTokenRequest request) {
        var caller = callerContext.required();
        permissionService.requirePermission(caller, "security:personal-token:create");
        Long userId = Long.valueOf(caller.subjectId());
        var issued = credentialService.issue(
                CredentialType.PERSONAL_ACCESS_TOKEN, userId, request.name(), request.scopes(),
                request.allowedIpCidrs(), request.expiresAt(), userId);
        return ApiResponse.success(IssuedTokenResponse.from(issued));
    }

    @GetMapping
    public ApiResponse<List<TokenSummary>> list() {
        var caller = callerContext.required();
        permissionService.requirePermission(caller, "security:personal-token:list");
        var records = credentialService.findBySubject(
                CredentialType.PERSONAL_ACCESS_TOKEN, Long.valueOf(caller.subjectId()));
        return ApiResponse.success(records.stream().map(TokenSummary::from).toList());
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> revoke(@PathVariable Long id) {
        var caller = callerContext.required();
        permissionService.requirePermission(caller, "security:personal-token:revoke");
        credentialService.revokeOwned(
                id, CredentialType.PERSONAL_ACCESS_TOKEN, Long.valueOf(caller.subjectId()));
        return ApiResponse.success();
    }
}
