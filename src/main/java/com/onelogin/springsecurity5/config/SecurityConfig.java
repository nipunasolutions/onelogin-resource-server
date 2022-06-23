package com.onelogin.springsecurity5.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .authorizationEndpoint(authorizationEndpoint ->
                                        authorizationEndpoint
                                                .authorizationRequestResolver(
                                                        new CustomAuthorizationRequestResolver(
                                                                clientRegistrationRepository))
                                )
                );
    }

    //@Bean
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

   /* @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.oneLoginClientRegistration());
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }*/



    /*
    *
    client:
        clientId: e53a4610-c8d7-013a-6829-020c9d8b8b0638672
        clientSecret: 9a8eee40d3d7966e2beb82cbacd76444b9489d000383de2d57ffbcf4c1a483ab
        accessTokenUri: https://financialwellnessgroup.onelogin.com/oidc/auth
        tokenName: access_token
        authenticationScheme: form
        clientAuthenticationScheme: form
        scope: [ email profile ]
      resource:
        userInfoUri: https://financialwellnessgroup.onelogin.com/oidc/2/me
        prefer-token-info: true
    * */
}


