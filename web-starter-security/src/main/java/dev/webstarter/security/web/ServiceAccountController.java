package dev.webstarter.security.web;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.security.token.AccessCredentialService;
import dev.webstarter.security.token.CredentialType;
import dev.webstarter.security.token.ServiceAccountService;
import dev.webstarter.security.web.SecurityManagementDtos.CreateServiceAccountRequest;
import dev.webstarter.security.web.SecurityManagementDtos.IssueTokenRequest;
import dev.webstarter.security.web.SecurityManagementDtos.IssuedTokenResponse;
import dev.webstarter.security.web.SecurityManagementDtos.ServiceAccountResponse;
import dev.webstarter.security.web.SecurityManagementDtos.TokenSummary;
import dev.webstarter.security.web.SecurityManagementDtos.UpdateServiceAccountRequest;

@RestController
@RequestMapping("/api/security/service-accounts")
public class ServiceAccountController {

    private static final String MANAGE = "security:service-account:manage";

    private final ServiceAccountService serviceAccountService;
    private final AccessCredentialService credentialService;
    private final CallerContext callerContext;
    private final PermissionService permissionService;

    public ServiceAccountController(
            ServiceAccountService serviceAccountService,
            AccessCredentialService credentialService,
            CallerContext callerContext,
            PermissionService permissionService) {
        this.serviceAccountService = serviceAccountService;
        this.credentialService = credentialService;
        this.callerContext = callerContext;
        this.permissionService = permissionService;
    }

    @GetMapping
    public ApiResponse<List<ServiceAccountResponse>> list() {
        requireManage();
        return ApiResponse.success(serviceAccountService.findAll().stream()
                .map(ServiceAccountResponse::from)
                .toList());
    }

    @PostMapping
    public ApiResponse<ServiceAccountResponse> create(
            @Valid @RequestBody CreateServiceAccountRequest request) {
        Long operatorId = requireManage();
        var account = serviceAccountService.create(
                request.code(), request.displayName(), request.description(), request.roleIds(), operatorId);
        return ApiResponse.success(ServiceAccountResponse.from(account));
    }

    @PutMapping("/{id}")
    public ApiResponse<ServiceAccountResponse> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateServiceAccountRequest request) {
        Long operatorId = requireManage();
        var account = serviceAccountService.update(
                id, request.displayName(), request.description(), request.enabled(),
                request.roleIds(), operatorId);
        return ApiResponse.success(ServiceAccountResponse.from(account));
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> disable(@PathVariable Long id) {
        serviceAccountService.disable(id, requireManage());
        return ApiResponse.success();
    }

    @PostMapping("/{id}/tokens")
    public ApiResponse<IssuedTokenResponse> issueToken(
            @PathVariable Long id,
            @Valid @RequestBody IssueTokenRequest request) {
        Long operatorId = requireManage();
        var account = serviceAccountService.required(id);
        if (!account.enabled()) {
            throw new IllegalArgumentException("Service account is disabled");
        }
        var issued = credentialService.issue(
                CredentialType.SERVICE_ACCOUNT_TOKEN, id, request.name(), request.scopes(),
                request.allowedIpCidrs(), request.expiresAt(), operatorId);
        return ApiResponse.success(IssuedTokenResponse.from(issued));
    }

    @GetMapping("/{id}/tokens")
    public ApiResponse<List<TokenSummary>> listTokens(@PathVariable Long id) {
        requireManage();
        return ApiResponse.success(credentialService.findBySubject(
                        CredentialType.SERVICE_ACCOUNT_TOKEN, id).stream()
                .map(TokenSummary::from)
                .toList());
    }

    @DeleteMapping("/{accountId}/tokens/{tokenId}")
    public ApiResponse<Void> revokeToken(
            @PathVariable Long accountId,
            @PathVariable Long tokenId) {
        requireManage();
        credentialService.revokeOwned(tokenId, CredentialType.SERVICE_ACCOUNT_TOKEN, accountId);
        return ApiResponse.success();
    }

    private Long requireManage() {
        var caller = callerContext.required();
        permissionService.requirePermission(caller, MANAGE);
        return Long.valueOf(caller.subjectId());
    }
}
