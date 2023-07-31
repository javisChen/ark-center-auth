package com.ark.center.auth.infra.config;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.DefaultAuthenticationEntryPoint;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.LoginUserDetailsService;
import com.ark.center.auth.infra.authentication.login.token.generate.JwtUserTokenGenerator;
import com.ark.center.auth.infra.authentication.login.token.generate.UserTokenGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
public class SecurityConfigB {

    @Bean
    public UserDetailsService userDetailsService(UserGateway userGateway) {
        return new LoginUserDetailsService(userGateway);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserTokenGenerator userTokenGenerator(JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        return new JwtUserTokenGenerator(jwtEncoder);
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                         PasswordEncoder passwordEncoder,
                                                         UserTokenGenerator userTokenGenerator
                                                         ) {
        LoginAuthenticationProvider provider = new LoginAuthenticationProvider(userTokenGenerator);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    @Bean
    public LoginAuthenticationFilter authenticationFilter(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter();
        loginAuthenticationFilter.setAuthenticationSuccessHandler(authenticationHandler);
        loginAuthenticationFilter.setAuthenticationFailureHandler(authenticationHandler);
        loginAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        loginAuthenticationFilter.setSecurityContextRepository(new SecurityContextRepository() {
            @Override
            public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
                return null;
            }

            @Override
            public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

            }

            @Override
            public boolean containsContext(HttpServletRequest request) {
                return false;
            }
        });
        return loginAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                           AuthenticationProvider authenticationProvider,
                                           LoginAuthenticationFilter loginAuthenticationFilter) throws Exception {
        httpSecurity.addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // 添加Provider
        httpSecurity.authenticationProvider(authenticationProvider);

        // 使用无状态Session
        httpSecurity.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        httpSecurity.formLogin(Customizer.withDefaults());
//
//        httpSecurity.oauth2ResourceServer(configurer -> {
//            configurer.jwt(new Customizer<OAuth2ResourceServerConfigurer<org.springframework.security.config.annotation.web.builders.HttpSecurity>.JwtConfigurer>() {
//                        @Override
//                        public void customize(OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
//                            jwtConfigurer.decoder(new NimbusJwtDecoder())
//                                    .jwtAuthenticationConverter()
//                        }
//                    })
//        });

        // 资源权限控制
        httpSecurity.authorizeHttpRequests(requests -> requests
                .requestMatchers(EndpointRequest.to(HealthEndpoint.class))
                    .permitAll()
                .requestMatchers("/login/account")
                    .permitAll()
                .requestMatchers("/admin/test")
                    .hasRole("ADMIN")
                .anyRequest()
                    .authenticated());

        // 权限不足时的处理
        httpSecurity.exceptionHandling(configurer -> configurer
                .accessDeniedHandler((request, response, accessDeniedException) -> response.getWriter().write("access denied"))
                .authenticationEntryPoint(new DefaultAuthenticationEntryPoint())
        );

        // 禁用csrf
        httpSecurity.csrf(AbstractHttpConfigurer::disable);
        return httpSecurity.build();
    }

}
