package dev.webstarter.security.web;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import dev.webstarter.security.persistence.model.AccessCredentialRecord;
import dev.webstarter.security.persistence.model.ServiceAccountRecord;
import dev.webstarter.security.token.IssuedCredential;
import dev.webstarter.security.token.ScopeCodec;

public final class SecurityManagementDtos {

    private SecurityManagementDtos() {
    }

    public record IssueTokenRequest(
            @NotBlank @Size(max = 100) String name,
            @NotEmpty Set<@NotBlank String> scopes,
            List<@NotBlank String> allowedIpCidrs,
            @Future Instant expiresAt) {
    }

    public record IssuedTokenResponse(
            Long id,
            String type,
            String token,
            String tokenHint,
            Set<String> scopes,
            Instant expiresAt) {

        public static IssuedTokenResponse from(IssuedCredential issued) {
            return new IssuedTokenResponse(
                    issued.id(), issued.credentialType().name(), issued.rawToken(),
                    issued.tokenHint(), issued.scopes(), issued.expiresAt());
        }
    }

    public record TokenSummary(
            Long id,
            String type,
            String name,
            String tokenHint,
            Set<String> scopes,
            List<String> allowedIpCidrs,
            Instant expiresAt,
            Instant revokedAt,
            Instant lastUsedAt,
            Instant createdAt) {

        public static TokenSummary from(AccessCredentialRecord record) {
            return new TokenSummary(
                    record.id(), record.credentialType().name(), record.name(), record.tokenHint(),
                    ScopeCodec.decode(record.scopes()), ScopeCodec.decodeLines(record.ipCidrs()),
                    record.expiresAt(), record.revokedAt(), record.lastUsedAt(), record.createdAt());
        }
    }

    public record CreateServiceAccountRequest(
            @NotBlank @Pattern(regexp = "[A-Za-z][A-Za-z0-9_-]{2,63}") String code,
            @NotBlank @Size(max = 100) String displayName,
            @Size(max = 500) String description,
            Set<Long> roleIds) {
    }

    public record UpdateServiceAccountRequest(
            @NotBlank @Size(max = 100) String displayName,
            @Size(max = 500) String description,
            boolean enabled,
            Set<Long> roleIds) {
    }

    public record ServiceAccountResponse(
            Long id,
            String code,
            String displayName,
            String description,
            boolean enabled,
            List<Long> roleIds,
            Instant createdAt,
            Instant updatedAt) {

        public static ServiceAccountResponse from(ServiceAccountRecord record) {
            return new ServiceAccountResponse(
                    record.id(), record.code(), record.displayName(), record.description(),
                    record.enabled(), ScopeCodec.decodeLongs(record.roleIds()),
                    record.createdAt(), record.updatedAt());
        }
    }
}
