package com.onelogin.springsecurity5.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.web.client.RestTemplate;

@Configuration
public class OAuth2Config {

    @Value("${spring.security.oauth2.provider.onelogin.clientId}")
    private String clientId;

    @Value("${spring.security.oauth2.provider.onelogin.clientSecret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.provider.onelogin.tokenUri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.provider.onelogin.authorizationUri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.provider.onelogin.userInfoUri}")
    private String userInfoUri;

    @Value("${spring.security.oauth2.provider.onelogin.userInfoUri}")
    private String jwkSetUri;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .build();

        var authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository);

        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.oneLoginClientRegistration());
    }

    private ClientRegistration oneLoginClientRegistration() {
        return ClientRegistration.withRegistrationId("onelogin")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // .redirectUriTemplate("{baseUrl}/login/oauth2/2/code/")
                .redirectUriTemplate("http://localhost:3000")
                .scope("openid", "profile", "email", "address", "phone")
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .userInfoUri(userInfoUri)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri(jwkSetUri)
                .clientName("OneLogin")
                .build();
    }
}
