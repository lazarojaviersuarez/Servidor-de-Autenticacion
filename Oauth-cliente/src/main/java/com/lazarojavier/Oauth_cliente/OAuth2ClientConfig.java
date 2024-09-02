//package com.lazarojavier.Oauth_cliente;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
//import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
//import org.springframework.security.oauth2.client.registration.ClientRegistration;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//
//@Configuration
//public class OAuth2ClientConfig {
//
//    @Bean
////    public ClientRegistrationRepository clientRegistrationRepository() {
////        ClientRegistration registration = ClientRegistration.withRegistrationId("myClient")
////                .clientId("your-client-id")
////                .clientSecret("your-client-secret")
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
////                .scope("read", "write")
////                .authorizationUri("https://example.com/oauth2/authorize")
////                .tokenUri("https://example.com/oauth2/token")
////                .userInfoUri("https://example.com/oauth2/userinfo")
////                .userNameAttributeName("id")
////                .clientName("My Client")
////                .build();
////
////        return new InMemoryClientRegistrationRepository(registration);
////    }
////}
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        ClientRegistration registration = ClientRegistration.withRegistrationId("myClient")
//
////    RegisteredOAuth2AuthorizedClient oauth_client = RegisteredClient.withId(UUID.randomUUID().toString())
//         .clientId("oauth-client")
//         .clientSecret("{noop}123456789")
//         .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//         .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//         .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//         .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oauth-client")
//         .redirectUri("http://127.0.0.1:8080/authorized")   //https://oauthdebugger.com/debug app de prueba
//        // .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
//         .scope(OidcScopes.OPENID)
//         .scope(OidcScopes.PROFILE)
//         .scope("read")
//         .scope("write")
//         //.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) una vez que quitamos esto el user pasara directamente
//         .build();
//        return new InMemoryClientRegistrationRepository(registration);
//        // return new InMemoryRegisteredClientRepository(oauth_client);
//}}