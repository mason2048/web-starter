package dev.webstarter.security.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;

import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.model.AccessCredentialRecord;

public final class AccessCredentialService {

    private static final Duration LAST_USED_WRITE_INTERVAL = Duration.ofMinutes(1);

    private final AccessCredentialMapper mapper;
    private final TokenHasher tokenHasher;
    private final CredentialScopePolicy scopePolicy;
    private final RawTokenFactory tokenFactory;
    private final Clock clock;

    public AccessCredentialService(
            AccessCredentialMapper mapper,
            TokenHasher tokenHasher,
            CredentialScopePolicy scopePolicy) {
        this(mapper, tokenHasher, scopePolicy, new RawTokenFactory(), Clock.systemUTC());
    }

    AccessCredentialService(
            AccessCredentialMapper mapper,
            TokenHasher tokenHasher,
            CredentialScopePolicy scopePolicy,
            RawTokenFactory tokenFactory,
            Clock clock) {
        this.mapper = mapper;
        this.tokenHasher = tokenHasher;
        this.scopePolicy = scopePolicy;
        this.tokenFactory = tokenFactory;
        this.clock = clock;
    }

    public IssuedCredential issue(
            CredentialType type,
            Long subjectId,
            String name,
            Collection<String> scopes,
            Collection<String> ipCidrs,
            Instant expiresAt,
            Long createdBy) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(subjectId, "subjectId");
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Credential name must not be blank");
        }
        Set<String> normalizedScopes = scopePolicy.validateCredentialScopes(type, subjectId, scopes);
        Instant now = clock.instant();
        if (expiresAt != null && !expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("Credential expiry must be in the future");
        }
        IpRestriction.validate(ipCidrs);
        String rawToken = tokenFactory.create(type);
        Long id = IdWorker.getId();
        String hint = rawToken.substring(0, Math.min(rawToken.length(), type.prefix().length() + 8));
        mapper.insert(new AccessCredentialRecord(
                id,
                type,
                subjectId,
                name.trim(),
                tokenHasher.hash(rawToken),
                hint,
                ScopeCodec.encode(normalizedScopes),
                ScopeCodec.encodeLines(ipCidrs),
                expiresAt,
                null,
                null,
                createdBy,
                now));
        return new IssuedCredential(id, type, rawToken, hint, normalizedScopes, expiresAt);
    }

    public AccessCredentialRecord findActiveByRawToken(String rawToken, String remoteAddress) {
        CredentialType expectedType = CredentialType.fromRawToken(rawToken);
        AccessCredentialRecord record = mapper.findByHash(tokenHasher.hash(rawToken));
        Instant now = clock.instant();
        if (record == null || record.credentialType() != expectedType || !record.activeAt(now)) {
            return null;
        }
        if (!IpRestriction.permits(remoteAddress, ScopeCodec.decodeLines(record.ipCidrs()))) {
            return null;
        }
        mapper.touchLastUsed(record.id(), now, now.minus(LAST_USED_WRITE_INTERVAL));
        return record;
    }

    public List<AccessCredentialRecord> findBySubject(CredentialType type, Long subjectId) {
        return mapper.findBySubject(type.name(), subjectId);
    }

    public void revoke(Long id) {
        if (mapper.revoke(id, clock.instant()) == 0) {
            throw new IllegalArgumentException("Credential does not exist");
        }
    }

    public void revokeOwned(Long id, CredentialType type, Long subjectId) {
        AccessCredentialRecord record = mapper.findById(id);
        if (record == null || record.credentialType() != type || !record.subjectId().equals(subjectId)) {
            throw new IllegalArgumentException("Credential does not exist");
        }
        revoke(id);
    }
}
