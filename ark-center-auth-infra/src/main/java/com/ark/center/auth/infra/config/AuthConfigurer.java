package com.ark.center.auth.infra.config;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationFilter;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationHandler;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationProvider;
import com.ark.center.auth.infra.authentication.cache.ApiCache;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.account.AccountLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.account.AccountLoginUserDetailsService;
import com.ark.center.auth.infra.authentication.login.sms.SmsLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.sms.SmsLoginUserDetailsService;
import com.ark.center.auth.infra.authentication.logout.AuthLogoutHandler;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.center.auth.infra.user.converter.UserConverter;
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
        ApiCache apiCache = context.getBean(ApiCache.class);
        UserPermissionService userPermissionService = context.getBean(UserPermissionService.class);

        // Filters
        addFilters(httpSecurity);

        // Providers
        addProviders(httpSecurity,
                loginAuthenticationProvider(),
                smsAuthenticationProvider(),
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

    private AccountLoginAuthenticationProvider loginAuthenticationProvider() {
        UserGateway userGateway = context.getBean(UserGateway.class);
        UserTokenGenerator userTokenGenerator = context.getBean(UserTokenGenerator.class);
        UserConverter userConverter = context.getBean(UserConverter.class);
        AccountLoginAuthenticationProvider provider = new AccountLoginAuthenticationProvider(userTokenGenerator);
        AccountLoginUserDetailsService detailsService = new AccountLoginUserDetailsService(userGateway, userConverter);
        provider.setUserDetailsService(detailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
    }

    private SmsLoginAuthenticationProvider smsAuthenticationProvider() {
        UserGateway userGateway = context.getBean(UserGateway.class);
        UserTokenGenerator userTokenGenerator = context.getBean(UserTokenGenerator.class);
        UserConverter userConverter = context.getBean(UserConverter.class);
        SmsLoginAuthenticationProvider provider = new SmsLoginAuthenticationProvider(userTokenGenerator, cacheService);
        SmsLoginUserDetailsService detailsService = new SmsLoginUserDetailsService(userGateway, userConverter);
        provider.setUserDetailsService(detailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
    }

    private void addProviders(HttpSecurity httpSecurity,
                              AccountLoginAuthenticationProvider accountLoginAuthenticationProvider,
                              SmsLoginAuthenticationProvider smsLoginAuthenticationProvider,
                              ApiAccessAuthenticationProvider apiAccessAuthenticationProvider) {
        httpSecurity
                .authenticationProvider(accountLoginAuthenticationProvider)
                .authenticationProvider(smsLoginAuthenticationProvider)
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
