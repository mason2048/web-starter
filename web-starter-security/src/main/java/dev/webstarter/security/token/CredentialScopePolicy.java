package dev.webstarter.security.token;

import java.util.Collection;
import java.util.Set;

public interface CredentialScopePolicy {

    Set<String> validateCredentialScopes(
            CredentialType credentialType,
            Long subjectId,
            Collection<String> scopes);

    Set<String> validateOAuthClientScopes(
            Collection<String> grantTypes,
            Long serviceAccountId,
            Collection<String> scopes);
}
