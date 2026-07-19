package dev.webstarter.security.oauth;

import java.time.Instant;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.token.TokenHasher;

public final class JtiRegistryValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID = new OAuth2Error(
            "invalid_token", "The access token is unknown or revoked", null);

    private final OAuthTokenRegistryMapper mapper;
    private final OAuthClientMapper clientMapper;
    private final TokenHasher tokenHasher;
    private final java.time.Clock clock;

    public JtiRegistryValidator(
            OAuthTokenRegistryMapper mapper,
            OAuthClientMapper clientMapper,
            TokenHasher tokenHasher) {
        this(mapper, clientMapper, tokenHasher, java.time.Clock.systemUTC());
    }

    JtiRegistryValidator(
            OAuthTokenRegistryMapper mapper,
            OAuthClientMapper clientMapper,
            TokenHasher tokenHasher,
            java.time.Clock clock) {
        this.mapper = mapper;
        this.clientMapper = clientMapper;
        this.tokenHasher = tokenHasher;
        this.clock = clock;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String jti = jwt.getId();
        if (jti == null) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        var record = mapper.findByJtiHash(tokenHasher.hash(jti));
        var client = record == null ? null : clientMapper.findByClientId(record.clientId());
        return record != null && record.activeAt(clock.instant()) && client != null && client.enabled()
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(INVALID);
    }
}
