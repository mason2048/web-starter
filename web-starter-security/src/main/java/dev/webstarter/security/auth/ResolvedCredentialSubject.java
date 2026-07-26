package dev.webstarter.security.auth;

import dev.webstarter.core.security.CurrentCaller;

/** Current RBAC snapshot together with the identity generation that issued credentials must match. */
public record ResolvedCredentialSubject(CurrentCaller caller, long securityEpoch) {
}
