package dev.webstarter.security.auth;

import java.util.Optional;

import dev.webstarter.core.security.CurrentCaller;

/** Resolves current RBAC state for credentials. Implementations must not cache permissions. */
public interface CredentialSubjectResolver {

    Optional<CurrentCaller> resolveUser(Long userId);

    Optional<CurrentCaller> resolveServiceAccount(Long serviceAccountId);
}
