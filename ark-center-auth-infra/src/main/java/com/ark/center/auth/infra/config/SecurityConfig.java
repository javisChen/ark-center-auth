//package com.ark.center.auth.infra.config;
//
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//
//import java.util.UUID;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    // http://127.0.0.1:8089/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8089/authorized
//
////    @Bean
////    @Order(1)
////    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
////            throws Exception {
////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
////                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
////        http
////                // Redirect to the login page when not authenticated from the
////                // authorization endpoint
////                .exceptionHandling((exceptions) -> exceptions
////                        .defaultAuthenticationEntryPointFor(
////                                new LoginUrlAuthenticationEntryPoint("/login"),
////                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
////                        )
////                )
////                // Accept access tokens for User Info and/or Client Registration
////                .oauth2ResourceServer(new Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>>() {
////                    @Override
////                    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> resourceServer) {
////                        resourceServer
////                                .jwt(Customizer.withDefaults());
////                    }
////                });
////
////        return http.build();
////    }
//
////    @Bean
////    @Order(2)
////    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
////            throws Exception {
////        http
////                .authorizeHttpRequests((authorize) -> authorize
////                        .anyRequest().authenticated()
////                )
////                // Form login handles the redirect to the login page from the
////                // authorization server filter chain
////                .formLogin(Customizer.withDefaults());
////
////        return http.build();
////    }
//
////    @Bean
////    public UserDetailsService userDetailsService() {
////        UserDetails userDetails = User.withDefaultPasswordEncoder()
////                .username("user")
////                .password("password")
////                .roles("USER")
////                .build();
////
////        return new InMemoryUserDetailsManager(userDetails);
////    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("messaging-client")
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .redirectUri("http://127.0.0.1:8089/login/oauth2/code/messaging-client-oidc")
//                .redirectUri("http://127.0.0.1:8089/authorized")
//                .scope(OidcScopes.OPENID)
//                .scope("message.read")
//                .scope("message.write")
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
//
//}