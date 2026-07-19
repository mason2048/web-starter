package dev.webstarter.security.oauth;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Adds {@code client_authentication_method=none} support for public-client refresh and revocation.
 *
 * <p>Spring Security's built-in public-client converter intentionally matches only the PKCE
 * authorization-code exchange. Public clients still need to identify themselves by an exact,
 * single {@code client_id} when rotating or revoking their bearer refresh tokens.
 */
public final class PublicClientNoneAuthenticationConverter implements AuthenticationConverter {

    static final String REQUEST_KIND = PublicClientNoneAuthenticationConverter.class.getName() + ".request-kind";
    static final String REFRESH_REQUEST = "refresh_token";
    static final String REVOCATION_REQUEST = "revocation";

    private final String tokenEndpoint;
    private final String revocationEndpoint;

    public PublicClientNoneAuthenticationConverter(AuthorizationServerSettings settings) {
        Assert.notNull(settings, "settings cannot be null");
        this.tokenEndpoint = settings.getTokenEndpoint();
        this.revocationEndpoint = settings.getTokenRevocationEndpoint();
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!HttpMethod.POST.matches(request.getMethod())
                || request.getQueryString() != null
                || !isFormRequest(request)
                || usesAnotherClientAuthenticationMethod(request)) {
            return null;
        }

        String path = requestPath(request);
        String requestKind;
        if (tokenEndpoint.equals(path)) {
            String[] grantTypes = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE);
            if (grantTypes == null
                    || grantTypes.length == 0
                    || !AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantTypes[0])) {
                return null;
            }
            requireSingleValue(grantTypes, OAuth2ParameterNames.GRANT_TYPE);
            requireSingleParameter(request, OAuth2ParameterNames.REFRESH_TOKEN);
            requestKind = REFRESH_REQUEST;
        }
        else if (revocationEndpoint.equals(path)) {
            requireSingleParameter(request, OAuth2ParameterNames.TOKEN);
            requestKind = REVOCATION_REQUEST;
        }
        else {
            return null;
        }

        String clientId = requireSingleParameter(request, OAuth2ParameterNames.CLIENT_ID);
        return new OAuth2ClientAuthenticationToken(
                clientId,
                ClientAuthenticationMethod.NONE,
                null,
                Map.of(REQUEST_KIND, requestKind));
    }

    private static boolean usesAnotherClientAuthenticationMethod(HttpServletRequest request) {
        return StringUtils.hasText(request.getHeader(HttpHeaders.AUTHORIZATION))
                || request.getParameterValues(OAuth2ParameterNames.CLIENT_SECRET) != null
                || request.getParameterValues(OAuth2ParameterNames.CLIENT_ASSERTION) != null
                || request.getParameterValues(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE) != null;
    }

    private static boolean isFormRequest(HttpServletRequest request) {
        try {
            return request.getContentType() != null
                    && MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(
                            MediaType.parseMediaType(request.getContentType()));
        }
        catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    private static String requestPath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        return StringUtils.hasText(contextPath) && requestUri.startsWith(contextPath)
                ? requestUri.substring(contextPath.length())
                : requestUri;
    }

    private static String requireSingleParameter(HttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        requireSingleValue(values, name);
        return values[0];
    }

    private static void requireSingleValue(String[] values, String name) {
        if (values == null || values.length != 1 || !StringUtils.hasText(values[0])) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    name + " must be supplied exactly once",
                    null));
        }
    }
}
