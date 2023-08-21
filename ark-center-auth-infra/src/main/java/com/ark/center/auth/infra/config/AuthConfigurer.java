package com.ark.center.auth.infra.config;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationFilter;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationHandler;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationProvider;
import com.ark.center.auth.infra.authentication.cache.ApiCache;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.LoginUserDetailsService;
import com.ark.center.auth.infra.authentication.logout.AuthLogoutHandler;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.component.cache.CacheService;
import com.ark.component.security.core.config.SecurityConfiguration;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;

public final class AuthConfigurer extends AbstractHttpConfigurer<AuthConfigurer, HttpSecurity> {

    private ApplicationContext context;

    @Override
    public void init(HttpSecurity http) throws Exception {
        context = http.getSharedObject(ApplicationContext.class);
        CacheService cacheService = context.getBean(CacheService.class);
        SecurityConfiguration.applyDefaultSecurity(http);
        configureLogout(http, cacheService);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        UserGateway userGateway = context.getBean(UserGateway.class);
        UserTokenGenerator userTokenGenerator = context.getBean(UserTokenGenerator.class);
        ApiCache apiCache = context.getBean(ApiCache.class);
        UserPermissionService userPermissionService = context.getBean(UserPermissionService.class);

        // Filters
        addFilters(httpSecurity);

        // Providers
        addProviders(httpSecurity,
                loginAuthenticationProvider(userGateway, userTokenGenerator),
                apiAccessAuthenticationProvider(apiCache, userPermissionService));

    }

    private void addFilters(HttpSecurity httpSecurity) {
        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);

        SecurityContextRepository securityContextRepository = context.getBean(SecurityContextRepository.class);

        addLoginFilters(httpSecurity, authenticationManager, securityContextRepository);

        addAuthFilters(httpSecurity, authenticationManager);
    }

    @NotNull
    private ApiAccessAuthenticationProvider apiAccessAuthenticationProvider(ApiCache apiCache, UserPermissionService userPermissionService) {
        return new ApiAccessAuthenticationProvider(apiCache, userPermissionService);
    }

    @NotNull
    private LoginAuthenticationProvider loginAuthenticationProvider(UserGateway userGateway, UserTokenGenerator userTokenGenerator) {
        LoginAuthenticationProvider loginAuthenticationProvider = new LoginAuthenticationProvider(userTokenGenerator);
        LoginUserDetailsService detailsService = new LoginUserDetailsService(userGateway);
        loginAuthenticationProvider.setUserDetailsService(detailsService);
        loginAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return loginAuthenticationProvider;
    }

    private void addProviders(HttpSecurity httpSecurity, LoginAuthenticationProvider loginAuthenticationProvider, ApiAccessAuthenticationProvider apiAccessAuthenticationProvider) {
        httpSecurity
                .authenticationProvider(loginAuthenticationProvider)
                .authenticationProvider(apiAccessAuthenticationProvider);
    }


    private void addAuthFilters(HttpSecurity httpSecurity, AuthenticationManager authenticationManager) {
        ApiAccessAuthenticationHandler authenticationHandler = new ApiAccessAuthenticationHandler();
        ApiAccessAuthenticationFilter filter = new ApiAccessAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setAuthenticationManager(authenticationManager);
        httpSecurity.addFilterBefore(filter, LoginAuthenticationFilter.class);
    }

    private void configureLogout(HttpSecurity httpSecurity, CacheService cacheService) throws Exception {
        AuthLogoutHandler handler = new AuthLogoutHandler(cacheService);
        httpSecurity.logout(configurer -> configurer
                .logoutUrl("/v1/logout")
                .clearAuthentication(false)
                .logoutSuccessHandler(handler)
                .addLogoutHandler(handler)
        );
    }

    private void addLoginFilters(HttpSecurity httpSecurity,
                                 AuthenticationManager authenticationManager,
                                 SecurityContextRepository contextRepository) {
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setSecurityContextRepository(contextRepository);
        filter.setAuthenticationManager(authenticationManager);
        httpSecurity.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
