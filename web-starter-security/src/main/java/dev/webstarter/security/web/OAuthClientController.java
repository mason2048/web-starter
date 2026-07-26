package dev.webstarter.security.web;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.webstarter.core.api.ApiResponse;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.security.oauth.OAuthClientManagementService;
import dev.webstarter.security.persistence.model.OAuthClientRecord;
import dev.webstarter.security.token.ScopeCodec;

@RestController
@RequestMapping("/api/security/oauth-clients")
public class OAuthClientController {

    private static final String MANAGE = "security:oauth-client:manage";

    private final OAuthClientManagementService clientService;
    private final CallerContext callerContext;
    private final PermissionService permissionService;

    public OAuthClientController(
            OAuthClientManagementService clientService,
            CallerContext callerContext,
            PermissionService permissionService) {
        this.clientService = clientService;
        this.callerContext = callerContext;
        this.permissionService = permissionService;
    }

    @GetMapping
    public ApiResponse<List<OAuthClientResponse>> list() {
        requireManage();
        return ApiResponse.success(clientService.findAll().stream().map(OAuthClientResponse::from).toList());
    }

    @PostMapping
    public ApiResponse<CreatedOAuthClientResponse> create(
            @Valid @RequestBody CreateOAuthClientRequest request) {
        requireManage();
        var created = clientService.create(
                request.clientId(), request.clientName(), request.authenticationMethods(),
                request.grantTypes(), request.redirectUris(), request.scopes(),
                request.requireConsent(), request.serviceAccountId());
        return ApiResponse.success(new CreatedOAuthClientResponse(
                OAuthClientResponse.from(created.client()), created.rawSecret()));
    }

    @PostMapping("/{id}/rotate-secret")
    public ApiResponse<CreatedOAuthClientResponse> rotateSecret(
            @PathVariable String id,
            @Valid @RequestBody(required = false) RotateOAuthClientSecretRequest request) {
        requireManage();
        var rotated = request == null || request.overlapSeconds() == null
                ? clientService.rotateSecret(id)
                : clientService.rotateSecret(id, Duration.ofSeconds(request.overlapSeconds()));
        return ApiResponse.success(new CreatedOAuthClientResponse(
                OAuthClientResponse.from(rotated.client()), rotated.rawSecret()));
    }

    @DeleteMapping("/{id}/retiring-secret")
    public ApiResponse<OAuthClientResponse> revokeRetiringSecret(@PathVariable String id) {
        requireManage();
        return ApiResponse.success(OAuthClientResponse.from(clientService.revokeRetiringSecret(id)));
    }

    @PutMapping("/{id}")
    public ApiResponse<OAuthClientResponse> update(
            @PathVariable String id,
            @Valid @RequestBody UpdateOAuthClientRequest request) {
        requireManage();
        return ApiResponse.success(OAuthClientResponse.from(clientService.update(
                id,
                request.clientName(),
                request.authenticationMethods(),
                request.grantTypes(),
                request.redirectUris(),
                request.scopes(),
                request.requireConsent(),
                request.serviceAccountId(),
                request.enabled())));
    }

    private void requireManage() {
        var caller = callerContext.required();
        permissionService.requirePermission(caller, MANAGE);
    }

    public record CreateOAuthClientRequest(
            @NotBlank @Size(max = 128) String clientId,
            @NotBlank @Size(max = 100) String clientName,
            @NotEmpty Set<String> authenticationMethods,
            @NotEmpty Set<String> grantTypes,
            Collection<String> redirectUris,
            @NotEmpty Set<String> scopes,
            boolean requireConsent,
            Long serviceAccountId) {
    }

    public record UpdateOAuthClientRequest(
            @NotBlank @Size(max = 100) String clientName,
            @NotEmpty Set<String> authenticationMethods,
            @NotEmpty Set<String> grantTypes,
            Collection<String> redirectUris,
            @NotEmpty Set<String> scopes,
            boolean requireConsent,
            Long serviceAccountId,
            boolean enabled) {
    }

    public record RotateOAuthClientSecretRequest(@Positive Long overlapSeconds) {
    }

    public record OAuthClientResponse(
            String id,
            String clientId,
            String clientName,
            Set<String> authenticationMethods,
            Set<String> grantTypes,
            List<String> redirectUris,
            Set<String> scopes,
            boolean requireConsent,
            boolean requirePkce,
            Long serviceAccountId,
            String clientSecretVersion,
            String retiringClientSecretVersion,
            Instant retiringClientSecretExpiresAt,
            Instant clientSecretRotatedAt,
            boolean enabled,
            Instant createdAt,
            Instant updatedAt) {

        static OAuthClientResponse from(OAuthClientRecord record) {
            return new OAuthClientResponse(
                    record.id(), record.clientId(), record.clientName(),
                    ScopeCodec.decode(record.authenticationMethods()),
                    ScopeCodec.decode(record.grantTypes()),
                    ScopeCodec.decodeLines(record.redirectUris()),
                    ScopeCodec.decode(record.scopes()), record.requireConsent(), record.requirePkce(),
                    record.serviceAccountId(), record.clientSecretVersion(),
                    record.retiringClientSecretVersion(), record.retiringClientSecretExpiresAt(),
                    record.clientSecretRotatedAt(), record.enabled(), record.createdAt(), record.updatedAt());
        }
    }

    public record CreatedOAuthClientResponse(OAuthClientResponse client, String clientSecret) {
    }
}
