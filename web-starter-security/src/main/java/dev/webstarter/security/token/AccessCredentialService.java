package dev.webstarter.security.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;
import org.springframework.transaction.annotation.Transactional;

import dev.webstarter.security.auth.CredentialSubjectResolver;
import dev.webstarter.security.auth.ResolvedCredentialSubject;
import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.model.AccessCredentialRecord;

public class AccessCredentialService {

    private static final Duration LAST_USED_WRITE_INTERVAL = Duration.ofMinutes(1);

    private final AccessCredentialMapper mapper;
    private final CredentialPepperKeyRing pepperKeyRing;
    private final CredentialScopePolicy scopePolicy;
    private final CredentialSubjectResolver subjectResolver;
    private final RawTokenFactory tokenFactory;
    private final Clock clock;

    public AccessCredentialService(
            AccessCredentialMapper mapper,
            TokenHasher tokenHasher,
            CredentialScopePolicy scopePolicy) {
        this(mapper, CredentialPepperKeyRing.single("v1", tokenHasher), scopePolicy,
                null, new RawTokenFactory(), Clock.systemUTC());
    }

    public AccessCredentialService(
            AccessCredentialMapper mapper,
            TokenHasher tokenHasher,
            CredentialScopePolicy scopePolicy,
            CredentialSubjectResolver subjectResolver) {
        this(mapper, CredentialPepperKeyRing.single("v1", tokenHasher), scopePolicy,
                subjectResolver, new RawTokenFactory(), Clock.systemUTC());
    }

    public AccessCredentialService(
            AccessCredentialMapper mapper,
            CredentialPepperKeyRing pepperKeyRing,
            CredentialScopePolicy scopePolicy,
            CredentialSubjectResolver subjectResolver) {
        this(mapper, pepperKeyRing, scopePolicy,
                subjectResolver, new RawTokenFactory(), Clock.systemUTC());
    }

    AccessCredentialService(
            AccessCredentialMapper mapper,
            TokenHasher tokenHasher,
            CredentialScopePolicy scopePolicy,
            RawTokenFactory tokenFactory,
            Clock clock) {
        this(mapper, tokenHasher, scopePolicy, null, tokenFactory, clock);
    }

    AccessCredentialService(
            AccessCredentialMapper mapper,
            TokenHasher tokenHasher,
            CredentialScopePolicy scopePolicy,
            CredentialSubjectResolver subjectResolver,
            RawTokenFactory tokenFactory,
            Clock clock) {
        this(mapper, CredentialPepperKeyRing.single("v1", tokenHasher), scopePolicy,
                subjectResolver, tokenFactory, clock);
    }

    AccessCredentialService(
            AccessCredentialMapper mapper,
            CredentialPepperKeyRing pepperKeyRing,
            CredentialScopePolicy scopePolicy,
            CredentialSubjectResolver subjectResolver,
            RawTokenFactory tokenFactory,
            Clock clock) {
        this.mapper = mapper;
        this.pepperKeyRing = pepperKeyRing;
        this.scopePolicy = scopePolicy;
        this.subjectResolver = subjectResolver;
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
        long subjectSecurityEpoch = resolveSecurityEpoch(type, subjectId);
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
                subjectSecurityEpoch,
                name.trim(),
                pepperKeyRing.hashWithActive(rawToken),
                pepperKeyRing.activeVersion(),
                hint,
                ScopeCodec.encode(normalizedScopes),
                ScopeCodec.encodeLines(ipCidrs),
                expiresAt,
                null,
                null,
                null,
                createdBy,
                now));
        return new IssuedCredential(id, type, rawToken, hint, normalizedScopes, expiresAt);
    }

    @Transactional
    public AccessCredentialRecord findActiveByRawToken(String rawToken, String remoteAddress) {
        CredentialType expectedType = CredentialType.fromRawToken(rawToken);
        Instant now = clock.instant();
        List<CredentialPepperKeyRing.HashCandidate> candidates = pepperKeyRing.lookupCandidates(rawToken);
        CredentialPepperKeyRing.HashCandidate active = candidates.getFirst();
        for (CredentialPepperKeyRing.HashCandidate candidate : candidates) {
            AccessCredentialRecord record = mapper.findByHashAndPepperVersion(
                    candidate.hash(), candidate.version());
            if (record == null) {
                continue;
            }
            if (record.credentialType() != expectedType || !record.activeAt(now)) {
                return null;
            }
            if (!IpRestriction.permits(remoteAddress, ScopeCodec.decodeLines(record.ipCidrs()))) {
                return null;
            }
            if (!candidate.active()) {
                record = migrateToActivePepper(record, candidate, active, now);
                if (record == null) {
                    return null;
                }
            }
            mapper.touchLastUsed(record.id(), now, now.minus(LAST_USED_WRITE_INTERVAL));
            return record;
        }
        return null;
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

    private long resolveSecurityEpoch(CredentialType type, Long subjectId) {
        if (subjectResolver == null) {
            return 0;
        }
        ResolvedCredentialSubject subject = (type == CredentialType.PERSONAL_ACCESS_TOKEN
                ? subjectResolver.resolveUser(subjectId)
                : subjectResolver.resolveServiceAccount(subjectId))
                .orElseThrow(() -> new IllegalArgumentException("Credential subject is unavailable"));
        return subject.securityEpoch();
    }

    private AccessCredentialRecord migrateToActivePepper(
            AccessCredentialRecord record,
            CredentialPepperKeyRing.HashCandidate retiring,
            CredentialPepperKeyRing.HashCandidate active,
            Instant authenticatedAt) {
        int migrated = mapper.migratePepper(
                record.id(), retiring.hash(), retiring.version(),
                active.hash(), active.version(), authenticatedAt);
        if (migrated == 1) {
            return record.withPepper(active.hash(), active.version());
        }
        AccessCredentialRecord concurrent = mapper.findByIdForUpdate(record.id());
        if (concurrent == null || !record.id().equals(concurrent.id())
                || !active.hash().equals(concurrent.tokenHash())
                || !active.version().equals(concurrent.pepperVersion())
                || !concurrent.activeAt(authenticatedAt)) {
            return null;
        }
        return concurrent;
    }
}
