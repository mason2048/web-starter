package dev.webstarter.security.oauth;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Writes {@code expires_in} from the access token's own issue and expiry
 * instants. Spring Security 7.1's default response converter subtracts the wall
 * clock at serialization time, which can expose a configured 600-second token
 * as 599 seconds even though the signed JWT lifetime is exactly 600 seconds.
 */
public final class ExactLifetimeAccessTokenResponseSuccessHandler
        implements AuthenticationSuccessHandler {

    private static final String RESPONSE_ERROR_DESCRIPTION =
            "Unable to process the access token response.";

    private final OAuth2AccessTokenResponseHttpMessageConverter responseConverter;

    public ExactLifetimeAccessTokenResponseSuccessHandler() {
        this.responseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
        this.responseConverter.setAccessTokenResponseParametersConverter(
                ExactLifetimeAccessTokenResponseSuccessHandler::parameters);
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        if (!(authentication instanceof OAuth2AccessTokenAuthenticationToken tokenAuthentication)) {
            throw serverError();
        }

        var accessToken = tokenAuthentication.getAccessToken();
        if (accessToken.getIssuedAt() == null || accessToken.getExpiresAt() == null) {
            throw serverError();
        }
        long lifetimeSeconds = ChronoUnit.SECONDS.between(
                accessToken.getIssuedAt(), accessToken.getExpiresAt());
        if (lifetimeSeconds <= 0) {
            throw serverError();
        }

        var responseBuilder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes())
                .expiresIn(lifetimeSeconds);
        if (tokenAuthentication.getRefreshToken() != null) {
            responseBuilder.refreshToken(tokenAuthentication.getRefreshToken().getTokenValue());
        }
        if (!CollectionUtils.isEmpty(tokenAuthentication.getAdditionalParameters())) {
            responseBuilder.additionalParameters(tokenAuthentication.getAdditionalParameters());
        }

        this.responseConverter.write(
                responseBuilder.build(),
                null,
                new ServletServerHttpResponse(response));
    }

    private static Map<String, Object> parameters(OAuth2AccessTokenResponse response) {
        var parameters = new LinkedHashMap<String, Object>(response.getAdditionalParameters());
        parameters.remove(OAuth2ParameterNames.ACCESS_TOKEN);
        parameters.remove(OAuth2ParameterNames.TOKEN_TYPE);
        parameters.remove(OAuth2ParameterNames.EXPIRES_IN);
        parameters.remove(OAuth2ParameterNames.SCOPE);
        parameters.remove(OAuth2ParameterNames.REFRESH_TOKEN);
        var accessToken = response.getAccessToken();
        if (accessToken.getIssuedAt() == null || accessToken.getExpiresAt() == null) {
            throw serverError();
        }
        long lifetimeSeconds = ChronoUnit.SECONDS.between(
                accessToken.getIssuedAt(), accessToken.getExpiresAt());
        if (lifetimeSeconds <= 0) {
            throw serverError();
        }

        parameters.put(OAuth2ParameterNames.ACCESS_TOKEN, accessToken.getTokenValue());
        parameters.put(OAuth2ParameterNames.TOKEN_TYPE, accessToken.getTokenType().getValue());
        parameters.put(OAuth2ParameterNames.EXPIRES_IN, lifetimeSeconds);
        if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
            parameters.put(
                    OAuth2ParameterNames.SCOPE,
                    StringUtils.collectionToDelimitedString(accessToken.getScopes(), " "));
        }
        if (response.getRefreshToken() != null) {
            parameters.put(OAuth2ParameterNames.REFRESH_TOKEN, response.getRefreshToken().getTokenValue());
        }
        return parameters;
    }

    private static OAuth2AuthenticationException serverError() {
        return new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                RESPONSE_ERROR_DESCRIPTION,
                null));
    }
}
