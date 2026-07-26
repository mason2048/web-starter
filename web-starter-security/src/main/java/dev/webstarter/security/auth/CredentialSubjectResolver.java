package dev.webstarter.security.auth;

import java.util.Optional;

/** Resolves current RBAC state for credentials. Implementations must not cache permissions. */
public interface CredentialSubjectResolver {

    Optional<ResolvedCredentialSubject> resolveUser(Long userId);

    Optional<ResolvedCredentialSubject> resolveServiceAccount(Long serviceAccountId);
}
