package dev.webstarter.security.config;

import java.time.Clock;
import java.util.List;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.PasswordHasher;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.security.auth.CredentialSubjectResolver;
import dev.webstarter.security.auth.CallerSnapshotRequestFilter;
import dev.webstarter.security.auth.IntersectingPermissionService;
import dev.webstarter.security.auth.InternalCredentialAuthenticationFilter;
import dev.webstarter.security.auth.InternalCredentialAuthenticationProvider;
import dev.webstarter.security.auth.OAuthOnlyBearerTokenResolver;
import dev.webstarter.security.auth.SpringPasswordHasher;
import dev.webstarter.security.auth.SpringSecurityCallerContext;
import dev.webstarter.security.auth.SystemCredentialSubjectResolver;
import dev.webstarter.security.auth.SystemUserDetailsService;
import dev.webstarter.security.oauth.AudienceValidator;
import dev.webstarter.security.oauth.DatabaseRegisteredClientRepository;
import dev.webstarter.security.oauth.ExactLifetimeAccessTokenResponseSuccessHandler;
import dev.webstarter.security.oauth.HashingOAuth2AuthorizationService;
import dev.webstarter.security.oauth.JtiRegistryValidator;
import dev.webstarter.security.oauth.JwtCallerAuthenticationConverter;
import dev.webstarter.security.oauth.McpBearerAuthenticationEntryPoint;
import dev.webstarter.security.oauth.OAuthClientManagementService;
import dev.webstarter.security.oauth.OAuthClientSecretPasswordEncoder;
import dev.webstarter.security.oauth.OAuthLoginAuthenticationEntryPoint;
import dev.webstarter.security.oauth.OAuthRefreshTokenFamilyService;
import dev.webstarter.security.oauth.PublicClientNoneAuthenticationConverter;
import dev.webstarter.security.oauth.PublicClientNoneAuthenticationProvider;
import dev.webstarter.security.oauth.PublicClientRefreshTokenGenerator;
import dev.webstarter.security.oauth.OAuthSigningKeyRing;
import dev.webstarter.security.oauth.TransactionalRefreshTokenAuthenticationProvider;
import dev.webstarter.security.oauth.WebStarterJwtCustomizer;
import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.persistence.mapper.OAuthClientMapper;
import dev.webstarter.security.persistence.mapper.OAuthRefreshTokenFamilyMapper;
import dev.webstarter.security.persistence.mapper.OAuthTokenRegistryMapper;
import dev.webstarter.security.persistence.mapper.ServiceAccountMapper;
import dev.webstarter.security.token.AccessCredentialService;
import dev.webstarter.security.token.CredentialScopePolicy;
import dev.webstarter.security.token.CredentialPepperKeyRing;
import dev.webstarter.security.token.DatabaseCredentialScopePolicy;
import dev.webstarter.security.token.ServiceAccountService;
import dev.webstarter.security.token.TokenHasher;
import dev.webstarter.security.login.LoginAttemptLimiter;
import dev.webstarter.security.login.LoginRateLimitProperties;
import dev.webstarter.security.login.RedisLoginAttemptLimiter;
import dev.webstarter.security.session.WebSessionManagementService;
import dev.webstarter.security.web.ApiAuthenticationEntryPoint;
import dev.webstarter.system.persistence.mapper.PermissionMapper;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.service.SystemIdentityService;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties({WebStarterSecurityProperties.class, LoginRateLimitProperties.class})
public class WebStarterSecurityConfiguration {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository clients,
            AuthorizationServerSettings authorizationServerSettings,
            TransactionalRefreshTokenAuthenticationProvider refreshTokenProvider,
            OAuthClientSecretPasswordEncoder clientSecretPasswordEncoder,
            CallerContext callerContext) throws Exception {
        AuthenticationProvider refreshTokenAdapter = new AuthenticationProvider() {
            @Override
            public org.springframework.security.core.Authentication authenticate(
                    org.springframework.security.core.Authentication authentication) {
                return refreshTokenProvider.authenticate(authentication);
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return refreshTokenProvider.supports(authentication);
            }
        };
        http.oauth2AuthorizationServer(authorizationServer -> {
            http.securityMatcher(authorizationServer.getEndpointsMatcher());
            authorizationServer.clientAuthentication(clientAuthentication -> clientAuthentication
                    .authenticationConverter(
                            new PublicClientNoneAuthenticationConverter(authorizationServerSettings))
                    .authenticationProvider(new PublicClientNoneAuthenticationProvider(clients))
                    .authenticationProviders(providers -> providers.forEach(provider -> {
                        if (provider instanceof ClientSecretAuthenticationProvider clientSecretProvider) {
                            clientSecretProvider.setPasswordEncoder(clientSecretPasswordEncoder);
                        }
                    })));
            authorizationServer.authorizationServerMetadataEndpoint(metadata -> metadata
                    .authorizationServerMetadataCustomizer(
                            WebStarterSecurityConfiguration::customizeAuthorizationServerMetadata));
            authorizationServer.authorizationEndpoint(endpoint -> endpoint.authenticationProviders(providers ->
                    providers.forEach(provider -> {
                        if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider codeProvider) {
                            codeProvider.setAuthenticationValidator(
                            WebStarterSecurityConfiguration::validateExactRedirectUri);
                        }
                    })));
            authorizationServer.tokenEndpoint(endpoint -> {
                endpoint.accessTokenResponseHandler(
                        new ExactLifetimeAccessTokenResponseSuccessHandler());
                endpoint.authenticationProviders(providers -> {
                    boolean replaced = false;
                    for (int index = 0; index < providers.size(); index++) {
                        if (providers.get(index) instanceof OAuth2RefreshTokenAuthenticationProvider) {
                            providers.set(index, refreshTokenAdapter);
                            replaced = true;
                        }
                    }
                    if (!replaced) {
                        throw new IllegalStateException(
                                "Spring Authorization Server refresh provider was not found");
                    }
                });
            });
        });
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                new OAuthLoginAuthenticationEntryPoint(),
                request -> "/oauth2/authorize".equals(request.getServletPath())));
        http.addFilterAfter(
                new CallerSnapshotRequestFilter(callerContext),
                SecurityContextHolderFilter.class);
        return http.build();
    }

    static void customizeAuthorizationServerMetadata(OAuth2AuthorizationServerMetadata.Builder metadata) {
        metadata.tokenEndpointAuthenticationMethods(methods -> {
            methods.clear();
            methods.addAll(List.of("none", "client_secret_basic", "client_secret_post"));
        });
        metadata.tokenRevocationEndpointAuthenticationMethods(methods -> {
            methods.clear();
            methods.addAll(List.of("none", "client_secret_basic", "client_secret_post"));
        });
        metadata.tokenIntrospectionEndpointAuthenticationMethods(methods -> {
            methods.clear();
            methods.addAll(List.of("client_secret_basic", "client_secret_post"));
        });
        metadata.grantTypes(grants -> {
            grants.clear();
            grants.addAll(List.of("authorization_code", "refresh_token", "client_credentials"));
        });
        metadata.responseTypes(responseTypes -> {
            responseTypes.clear();
            responseTypes.add("code");
        });
        metadata.codeChallengeMethods(methods -> {
            methods.clear();
            methods.add("S256");
        });
        metadata.tlsClientCertificateBoundAccessTokens(false);
        metadata.claims(claims -> claims.remove(
                OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED));
    }

    @Bean
    @Order(2)
    SecurityFilterChain mcpSecurityFilterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            WebStarterSecurityProperties properties,
            JwtDecoder jwtDecoder,
            CredentialSubjectResolver subjectResolver) throws Exception {
        var entryPoint = new McpBearerAuthenticationEntryPoint(properties);
        var internalFilter = new InternalCredentialAuthenticationFilter(
                authenticationManager, entryPoint, properties.internalTokensEnabled());
        http.securityMatcher("/mcp", "/mcp/**")
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(context -> context.requireExplicitSave(false))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .authenticationEntryPoint(entryPoint)
                        .bearerTokenResolver(new OAuthOnlyBearerTokenResolver())
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(
                                        new JwtCallerAuthenticationConverter(subjectResolver))))
                .addFilterBefore(internalFilter, BearerTokenAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain webSecurityFilterChain(HttpSecurity http, CallerContext callerContext) throws Exception {
        CookieCsrfTokenRepository csrf = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrf.setCookieName("XSRF-TOKEN");
        csrf.setHeaderName("X-XSRF-TOKEN");
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/csrf",
                                "/.well-known/oauth-protected-resource/**",
                                "/error")
                        .permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .csrf(configurer -> configurer.csrfTokenRepository(csrf))
                .securityContext(context -> context
                        .securityContextRepository(securityContextRepository()))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(fixation -> fixation.migrateSession()))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new ApiAuthenticationEntryPoint()))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("WEB_STARTER_SESSION")
                        .logoutSuccessHandler((request, response, authentication) ->
                                response.setStatus(204)))
                .addFilterAfter(new CallerSnapshotRequestFilter(callerContext), SecurityContextHolderFilter.class);
        return http.build();
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(),
                new HttpSessionSecurityContextRepository());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    PasswordHasher passwordHasher(PasswordEncoder passwordEncoder) {
        return new SpringPasswordHasher(passwordEncoder);
    }

    @Bean
    OAuthClientSecretPasswordEncoder oauthClientSecretPasswordEncoder(PasswordEncoder passwordEncoder) {
        return new OAuthClientSecretPasswordEncoder(passwordEncoder);
    }

    @Bean
    TokenHasher tokenHasher(WebStarterSecurityProperties properties) {
        return new TokenHasher(properties.requiredTokenPepper());
    }

    @Bean
    CredentialPepperKeyRing credentialPepperKeyRing(WebStarterSecurityProperties properties) {
        return CredentialPepperKeyRing.from(properties);
    }

    @Bean
    UserDetailsService userDetailsService(SystemIdentityService identityService) {
        return new SystemUserDetailsService(identityService);
    }

    @Bean
    CredentialSubjectResolver credentialSubjectResolver(
            SystemIdentityService identityService,
            ServiceAccountMapper serviceAccountMapper) {
        return new SystemCredentialSubjectResolver(identityService, serviceAccountMapper);
    }

    @Bean
    CallerContext callerContext(CredentialSubjectResolver subjectResolver) {
        return new SpringSecurityCallerContext(subjectResolver);
    }

    @Bean
    PermissionService permissionService() {
        return new IntersectingPermissionService();
    }

    @Bean
    CredentialScopePolicy credentialScopePolicy(
            SystemIdentityService identityService,
            ServiceAccountMapper serviceAccountMapper,
            PermissionMapper permissionMapper) {
        return new DatabaseCredentialScopePolicy(identityService, serviceAccountMapper, permissionMapper);
    }

    @Bean
    AccessCredentialService accessCredentialService(
            AccessCredentialMapper mapper,
            CredentialPepperKeyRing pepperKeyRing,
            CredentialScopePolicy scopePolicy,
            CredentialSubjectResolver subjectResolver) {
        return new AccessCredentialService(mapper, pepperKeyRing, scopePolicy, subjectResolver);
    }

    @Bean
    ServiceAccountService serviceAccountService(
            ServiceAccountMapper mapper,
            RoleMapper roleMapper,
            AccessCredentialMapper credentialMapper,
            OAuthTokenRegistryMapper oauthTokenRegistryMapper) {
        return new ServiceAccountService(
                mapper, roleMapper, credentialMapper, oauthTokenRegistryMapper);
    }

    @Bean
    WebSessionManagementService webSessionManagementService(
            FindByIndexNameSessionRepository<? extends Session> sessions,
            TokenHasher tokenHasher) {
        return new WebSessionManagementService(sessions, tokenHasher);
    }

    @Bean
    LoginAttemptLimiter loginAttemptLimiter(
            StringRedisTemplate redis,
            TokenHasher tokenHasher,
            LoginRateLimitProperties properties) {
        return new RedisLoginAttemptLimiter(redis, tokenHasher, properties);
    }

    @Bean
    OAuthClientManagementService oauthClientManagementService(
            OAuthClientMapper mapper,
            OAuthClientSecretPasswordEncoder passwordEncoder,
            CredentialScopePolicy scopePolicy,
            WebStarterSecurityProperties properties) {
        return new OAuthClientManagementService(mapper, passwordEncoder, scopePolicy, properties);
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(
            OAuthClientMapper mapper,
            WebStarterSecurityProperties properties) {
        return new DatabaseRegisteredClientRepository(mapper, properties);
    }

    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository clients,
            OAuthTokenRegistryMapper tokenRegistry,
            OAuthRefreshTokenFamilyService refreshTokenFamilies,
            TokenHasher tokenHasher) {
        var jdbcDelegate = new JdbcOAuth2AuthorizationService(jdbcOperations, clients);
        return new HashingOAuth2AuthorizationService(
                jdbcDelegate, clients, tokenRegistry, refreshTokenFamilies, tokenHasher);
    }

    @Bean
    OAuthRefreshTokenFamilyService oauthRefreshTokenFamilyService(
            OAuthRefreshTokenFamilyMapper mapper) {
        return new OAuthRefreshTokenFamilyService(mapper);
    }

    @Bean
    TransactionalRefreshTokenAuthenticationProvider transactionalRefreshTokenAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        return new TransactionalRefreshTokenAuthenticationProvider(
                authorizationService, tokenGenerator);
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, clients);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(WebStarterSecurityProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.issuer()).build();
    }

    @Bean
    Clock oauthSigningKeyLifecycleClock() {
        return Clock.systemUTC();
    }

    @Bean
    OAuthSigningKeyRing oauthSigningKeyRing(
            WebStarterSecurityProperties properties,
            Clock oauthSigningKeyLifecycleClock) {
        return OAuthSigningKeyRing.from(properties, oauthSigningKeyLifecycleClock);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(OAuthSigningKeyRing keyRing) {
        return (selector, context) -> selector.select(keyRing.jwkSet());
    }

    @Bean
    JwtEncoder jwtEncoder(
            JWKSource<SecurityContext> jwkSource,
            OAuthSigningKeyRing keyRing) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        encoder.setJwkSelector(keyRing::selectActiveSigningKey);
        return encoder;
    }

    @Bean
    OAuth2TokenGenerator<? extends OAuth2Token> oauth2TokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                new OAuth2AccessTokenGenerator(),
                new PublicClientRefreshTokenGenerator(),
                new OAuth2RefreshTokenGenerator());
    }

    @Bean
    JwtDecoder jwtDecoder(
            JWKSource<SecurityContext> jwkSource,
            WebStarterSecurityProperties properties,
            OAuthTokenRegistryMapper tokenRegistry,
            OAuthClientMapper oauthClientMapper,
            TokenHasher tokenHasher) {
        JwtDecoder decoder = org.springframework.security.oauth2.jwt.NimbusJwtDecoder
                .withJwkSource(jwkSource)
                .build();
        if (decoder instanceof org.springframework.security.oauth2.jwt.NimbusJwtDecoder nimbus) {
            nimbus.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    JwtValidators.createDefaultWithIssuer(properties.issuer()),
                    new AudienceValidator(properties.resourceAudience()),
                    new JtiRegistryValidator(tokenRegistry, oauthClientMapper, tokenHasher)));
        }
        return decoder;
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(
            CredentialSubjectResolver subjectResolver,
            WebStarterSecurityProperties properties) {
        return new WebStarterJwtCustomizer(subjectResolver, properties);
    }

    @Bean
    AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            AccessCredentialService credentialService,
            CredentialSubjectResolver subjectResolver) {
        DaoAuthenticationProvider web = new DaoAuthenticationProvider(userDetailsService);
        web.setPasswordEncoder(passwordEncoder);
        var internal = new InternalCredentialAuthenticationProvider(credentialService, subjectResolver);
        return new ProviderManager(web, internal);
    }

    static void validateExactRedirectUri(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken authentication = context.getAuthentication();
        String requested = authentication.getRedirectUri();
        if (requested == null || !context.getRegisteredClient().getRedirectUris().contains(requested)) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "OAuth redirect_uri must exactly match a registered URI",
                            null),
                    // Never attach an unvalidated redirect URI to the exception. The
                    // authorization endpoint redirects errors whenever this token carries one.
                    null);
        }
        new OAuth2AuthorizationCodeRequestAuthenticationValidator().accept(context);
    }
}
