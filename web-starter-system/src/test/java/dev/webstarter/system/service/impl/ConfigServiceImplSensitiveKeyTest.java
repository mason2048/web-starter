package dev.webstarter.system.service.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ConfigServiceImplSensitiveKeyTest {

    @ParameterizedTest
    @MethodSource("sensitiveKeys")
    void recognizesNormalizedSecretKeyVariants(String key) {
        assertThat(ConfigServiceImpl.isSensitiveKey(key)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("ordinaryKeys")
    void doesNotRejectOrdinaryConfigurationKeys(String key) {
        assertThat(ConfigServiceImpl.isSensitiveKey(key)).isFalse();
    }

    private static Stream<String> sensitiveKeys() {
        return Stream.of(
                "database.password",
                "database.passwd",
                "database.passphrase",
                "oauth.clientSecret",
                "agent-token",
                "service_credential",
                "oauth.private-key",
                "oauth.privateKey",
                "oauth.privatekey",
                "oauth.signing-key",
                "oauth.signingKey",
                "storage.encryption_key",
                "integration.api-key",
                "integration.apiKey",
                "integration.apikey",
                "cloud.access-key",
                "cloud.authKey",
                "crypto.master-key",
                "http.authorization",
                "session.cookie-name",
                "tls.key-store",
                "tls.trustStore");
    }

    private static Stream<String> ordinaryKeys() {
        return Stream.of(
                "search.keyword",
                "project.key-prefix",
                "oauth.public-key-id",
                "system.page-size",
                "feature.enabled");
    }
}
