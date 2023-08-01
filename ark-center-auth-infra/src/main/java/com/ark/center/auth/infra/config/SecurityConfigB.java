package com.ark.center.auth.infra.config;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.DefaultAuthenticationEntryPoint;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.LoginUserDetailsService;
import com.ark.center.auth.infra.authentication.token.cache.RedisSecurityContextRepository;
import com.ark.center.auth.infra.authentication.token.generate.JwtUserTokenGenerator;
import com.ark.center.auth.infra.authentication.token.generate.UserTokenGenerator;
import com.ark.component.cache.CacheService;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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
    public LoginAuthenticationFilter authenticationFilter(AuthenticationConfiguration authenticationConfiguration,
                                                          SecurityContextRepository securityContextRepository) throws Exception {
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter();
        loginAuthenticationFilter.setAuthenticationSuccessHandler(authenticationHandler);
        loginAuthenticationFilter.setAuthenticationFailureHandler(authenticationHandler);
        loginAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        loginAuthenticationFilter.setSecurityContextRepository(securityContextRepository);
        return loginAuthenticationFilter;
    }

    @Bean
    public SecurityContextRepository securityContextRepository(CacheService cacheService) {
        return new RedisSecurityContextRepository(cacheService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                           AuthenticationProvider authenticationProvider,
                                           LoginAuthenticationFilter loginAuthenticationFilter,
                                           SecurityContextRepository securityContextRepository) throws Exception {
        httpSecurity.securityContext(new Customizer<SecurityContextConfigurer<HttpSecurity>>() {
            @Override
            public void customize(SecurityContextConfigurer<HttpSecurity> configurer) {
                configurer.securityContextRepository(securityContextRepository);
            }
        });
        httpSecurity.addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // 添加Provider
        httpSecurity.authenticationProvider(authenticationProvider);

        // 暂时禁用SessionManagement
        httpSecurity.sessionManagement(AbstractHttpConfigurer::disable);

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
