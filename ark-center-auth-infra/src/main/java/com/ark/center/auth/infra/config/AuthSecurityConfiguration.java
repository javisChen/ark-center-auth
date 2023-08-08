package com.ark.center.auth.infra.config;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationFilter;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationProvider;
import com.ark.center.auth.infra.authentication.api.ApiCacheHolder;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.LoginUserDetailsService;
import com.ark.center.auth.infra.authentication.logout.AuthLogoutHandler;
import com.ark.center.auth.infra.authentication.token.generator.JwtUserTokenGenerator;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.component.cache.CacheService;
import com.ark.component.security.core.config.SecurityConfiguration;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
//@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AuthSecurityConfiguration {

    @Bean
    public UserDetailsService userDetailsService(UserGateway userGateway) {
        return new LoginUserDetailsService(userGateway);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserTokenGenerator userTokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        return new JwtUserTokenGenerator(jwtEncoder);
    }

//    @Bean
//    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
//                                                         PasswordEncoder passwordEncoder,
//                                                         UserTokenGenerator userTokenGenerator) {
//        LoginAuthenticationProvider provider = new LoginAuthenticationProvider(userTokenGenerator);
//        provider.setPasswordEncoder(passwordEncoder);
//        provider.setUserDetailsService(userDetailsService);
//        return provider;
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   ApplicationContext applicationContext) throws Exception {

        SecurityConfiguration.applyDefaultSecurity(httpSecurity);
        AuthenticationConfiguration authenticationConfiguration = applicationContext.getBean(AuthenticationConfiguration.class);
//        AuthenticationProvider authenticationProvider = applicationContext.getBean(AuthenticationProvider.class);
        SecurityContextRepository securityContextRepository = applicationContext.getBean(SecurityContextRepository.class);
        CacheService cacheService = applicationContext.getBean(CacheService.class);
        UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
        PasswordEncoder passwordEncoder = applicationContext.getBean(PasswordEncoder.class);
        UserTokenGenerator userTokenGenerator = applicationContext.getBean(UserTokenGenerator.class);
        ApiCacheHolder apiCacheHolder = applicationContext.getBean(ApiCacheHolder.class);
        UserPermissionService userPermissionService = applicationContext.getBean(UserPermissionService.class);

        LoginAuthenticationProvider loginAuthenticationProvider = new LoginAuthenticationProvider(userTokenGenerator);
        loginAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        loginAuthenticationProvider.setUserDetailsService(userDetailsService);

        ApiAccessAuthenticationProvider apiAccessAuthenticationProvider = new ApiAccessAuthenticationProvider(apiCacheHolder, userPermissionService);

        registerLogout(httpSecurity, cacheService);

        addLoginFilters(httpSecurity, authenticationConfiguration, securityContextRepository);

        addAuthFilters(httpSecurity, authenticationConfiguration);

        httpSecurity.authenticationProvider(loginAuthenticationProvider)
                .authenticationProvider(apiAccessAuthenticationProvider);

        return httpSecurity.build();
    }


    private void addAuthFilters(HttpSecurity httpSecurity, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        ApiAccessAuthenticationFilter filter = new ApiAccessAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        httpSecurity.addFilterBefore(filter, LoginAuthenticationFilter.class);
    }


    private void registerLogout(HttpSecurity httpSecurity, CacheService cacheService) throws Exception {
        AuthLogoutHandler handler = new AuthLogoutHandler(cacheService);
        httpSecurity.logout(configurer -> configurer
                .clearAuthentication(false)
                .logoutSuccessHandler(handler)
                .addLogoutHandler(handler)
        );
    }

    private void addLoginFilters(HttpSecurity httpSecurity,
                                 AuthenticationConfiguration authenticationConfiguration,
                                 SecurityContextRepository contextRepository) throws Exception {
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        filter.setSecurityContextRepository(contextRepository);
        httpSecurity.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

}
