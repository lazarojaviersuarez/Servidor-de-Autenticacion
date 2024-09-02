package com.example.Auth20.Oauth;


    import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

    import lombok.extern.slf4j.Slf4j;
    import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        @Order(1)
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
                throws Exception {
            OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);//Aplica la configuración de seguridad predeterminada para el servidor de autorización.
            http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                    .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
            http
                    // Redirect to the login page when not authenticated from the
                    // authorization endpoint
                    .exceptionHandling((exceptions) -> exceptions
                            .defaultAuthenticationEntryPointFor(
                                    new LoginUrlAuthenticationEntryPoint("/login"),
                                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                            )
                    )
                    // Accept access tokens for User Info and/or Client Registration
                    .oauth2ResourceServer((resourceServer) -> resourceServer
                            .jwt(Customizer.withDefaults()));

            return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
                throws Exception {
            http
                    .authorizeHttpRequests((authorize) -> authorize
                            .anyRequest().authenticated()
                    )
                    .csrf(csrf-> csrf.disable())// siempre desabilitamos el csrf
                    // Form login handles the redirect to the login page from the
                    // authorization server filter chain
                    .formLogin(Customizer.withDefaults());

            return http.build();
        }

        @Bean
        public UserDetailsService userDetailsService() {
            UserDetails userDetails = User.builder()//withDefaultPasswordEncoder()
                    .username("postgres")
                    .password("{noop}1234")
                    .roles("USER")
                    .build();

            return new InMemoryUserDetailsManager(userDetails);
        }

        @Bean
        public RegisteredClientRepository registeredClientRepository() {
            RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("oidc-client")
                    .clientSecret("{noop}243432532")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://oauthdebugger.com/debug")   //https://oauthdebugger.com/debug app de prueba
                    .postLogoutRedirectUri("http://127.0.0.1:8080/")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    //.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) una vez que quitamos esto el user pasara directamente
                    .build();

            RegisteredClient oauth_client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("oauth-client")
                    .clientSecret("{noop}123456789")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oauth-client")
                    .redirectUri("http://127.0.0.1:8080/authorized")   //https://oauthdebugger.com/debug app de prueba
                    .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    //.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) una vez que quitamos esto el user pasara directamente
                    .build();

            return new InMemoryRegisteredClientRepository(oidcClient,oauth_client);
        }

        @Bean
        public JWKSource<SecurityContext> jwkSource() {
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);
        }

        private static KeyPair generateRsaKey() {
            KeyPair keyPair;
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                keyPair = keyPairGenerator.generateKeyPair();
            }
            catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
            return keyPair;
        }

        @Bean
        public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
            return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        }

        @Bean
        public AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
        }


    }

//        Esta configuración de Spring Boot para OAuth 2.0 utiliza varios componentes y métodos para establecer una seguridad basada en OAuth 2.0 y OpenID Connect (OIDC). A continuación, se explica cada método y línea de código relevante:
//
//        Configuración General
//@Configuration: Indica que esta clase es una fuente de definiciones de beans para la aplicación Spring.
//@EnableWebSecurity: Habilita el soporte de seguridad web en la aplicación, permitiendo la personalización de la seguridad.
//        Bean authorizationServerSecurityFilterChain
//        Este bean define la cadena de filtros de seguridad para el servidor de autorización OAuth 2.0.
//
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http): Aplica la configuración de seguridad predeterminada para el servidor de autorización.
//        .oidc(Customizer.withDefaults()): Habilita OpenID Connect 1.0 con configuraciones predeterminadas.
//        .exceptionHandling(...): Define cómo manejar excepciones de autenticación, redirigiendo a la página de inicio de sesión cuando no está autenticado.
//        .oauth2ResourceServer(...): Configura el servidor de recursos OAuth 2.0 para aceptar tokens JWT.
//        Bean defaultSecurityFilterChain
//        Define la cadena de filtros de seguridad predeterminada para la aplicación.
//
//        .authorizeHttpRequests(...): Requiere autenticación para todas las solicitudes.
//        .csrf(csrf-> csrf.disable()): Deshabilita CSRF protección.
//        .formLogin(Customizer.withDefaults()): Configura el inicio de sesión basado en formularios.
//        Bean userDetailsService
//        Implementa UserDetailsService para cargar detalles del usuario desde memoria.
//
//        User.withDefaultPasswordEncoder()...: Crea un usuario con roles y contraseñas codificadas.
//        new InMemoryUserDetailsManager(userDetails): Gestiona los detalles del usuario en memoria.
//        Bean registeredClientRepository
//        Registra un cliente OIDC en memoria.
//
//        RegisteredClient.withId(...) y siguientes llamadas: Configuran el cliente OIDC con ID, secret, métodos de autenticación, tipos de concesión, URI de redirección, escopos y configuraciones.
//        new InMemoryRegisteredClientRepository(oidcClient): Gestiona clientes registrados en memoria.
//        Bean jwkSource
//        Genera una fuente de claves JSON Web Key (JWK) para la decodificación de tokens JWT.
//
//        generateRsaKey(): Genera un par de claves RSA.
//        new RSAKey.Builder(publicKey)...: Construye una clave RSA con ID único.
//        new JWKSet(rsaKey): Crea un conjunto de claves JWK.
//        new ImmutableJWKSet<>(jwkSet): Retorna una fuente inmutable de claves JWK.
//        Bean jwtDecoder
//        Decodifica tokens JWT usando la fuente de claves generada anteriormente.
//
//        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource): Utiliza la fuente de claves para decodificar tokens JWT.
//        Bean authorizationServerSettings
//        Establece configuraciones para el servidor de autorización.
//
//        AuthorizationServerSettings.builder().build(): Crea configuraciones predeterminadas para el servidor de autorización.
//        Resumen
//        Esta configuración establece una aplicación Spring Boot segura con OAuth 2.0 y OpenID Connect, incluyendo la configuración del servidor de autorización, la gestión de usuarios y clientes, y la decodificación de tokens JWT. Cada componente juega un papel crucial en asegurar la comunicación entre el cliente y el servidor, gestionando la autenticación y autorización de usuarios y clientes.
//
