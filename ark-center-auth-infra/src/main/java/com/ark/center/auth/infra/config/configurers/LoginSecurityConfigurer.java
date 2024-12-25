package com.ark.center.auth.infra.config.configurers;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationConverter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.account.AccountLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.mobile.MobileLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.component.cache.CacheService;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class LoginSecurityConfigurer extends AbstractHttpConfigurer<LoginSecurityConfigurer, HttpSecurity> {

    private ApplicationContext context;

    @Override
    public void init(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        context = http.getSharedObject(ApplicationContext.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder
                .authenticationEventPublisher(new DefaultAuthenticationEventPublisher())
                .authenticationProvider(buildAccountLoginAuthenticationProvider(context))
                .authenticationProvider(buildMobileLoginAuthenticationProvider(context))
                .build();
        http.authenticationManager(authenticationManager);
        http.setSharedObject(AuthenticationManager.class, authenticationManager);

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        // 配置登录过滤器
        configureLoginFilter(http, context, authenticationManager);
    }

    @SuppressWarnings("rawtypes")
    private void configureLoginFilter(HttpSecurity http, 
                                    ApplicationContext context, 
                                    AuthenticationManager authenticationManager) {
        SecurityContextRepository contextRepository = context.getBean(SecurityContextRepository.class);
        List<LoginAuthenticationConverter> converters = new ArrayList<>(
            context.getBeansOfType(LoginAuthenticationConverter.class).values()
        );
        
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter(converters);
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setSecurityContextRepository(contextRepository);
        filter.setAuthenticationManager(authenticationManager);
        
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    @NotNull
    private MobileLoginAuthenticationProvider buildMobileLoginAuthenticationProvider(ApplicationContext context) {
        return new MobileLoginAuthenticationProvider(
            context.getBean(UserTokenGenerator.class),
            context.getBean(UserGateway.class),
            context.getBean(CacheService.class),
            context.getBean(UserConverter.class)
        );
    }

    @NotNull
    private AccountLoginAuthenticationProvider buildAccountLoginAuthenticationProvider(ApplicationContext context) {
        AccountLoginAuthenticationProvider accountProvider = new AccountLoginAuthenticationProvider(
            context.getBean(UserTokenGenerator.class),
            context.getBean(UserGateway.class),
            context.getBean(UserConverter.class)
        );
        accountProvider.setPasswordEncoder(context.getBean(PasswordEncoder.class));
        return accountProvider;
    }
} 