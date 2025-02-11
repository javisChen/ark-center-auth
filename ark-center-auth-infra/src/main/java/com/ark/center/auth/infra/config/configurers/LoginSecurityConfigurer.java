package com.ark.center.auth.infra.config.configurers;

import com.ark.center.auth.infra.application.service.ApplicationAuthConfigService;
import com.ark.center.auth.infra.authentication.LoginAuthenticationDetailsSource;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationConverter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.account.AccountLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.mobile.MobileLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.userdetails.IamUserDetailsService;
import com.ark.center.auth.infra.authentication.token.issuer.TokenIssuer;
import com.ark.center.auth.infra.captcha.SmsCaptchaProvider;
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
        ApplicationAuthConfigService applicationAuthConfigService = context.getBean(ApplicationAuthConfigService.class);
        List<LoginAuthenticationConverter> converters = new ArrayList<>(
            context.getBeansOfType(LoginAuthenticationConverter.class).values()
        );

        LoginAuthenticationFilter filter = buildLoginAuthenticationFilter(
            authenticationManager, 
            converters, 
            contextRepository,
            applicationAuthConfigService
        );

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    @NotNull
    private LoginAuthenticationFilter buildLoginAuthenticationFilter(AuthenticationManager authenticationManager,
                                                                   List<LoginAuthenticationConverter> converters,
                                                                   SecurityContextRepository contextRepository,
                                                                   ApplicationAuthConfigService applicationAuthConfigService) {
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter(converters, applicationAuthConfigService);
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setSecurityContextRepository(contextRepository);
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationDetailsSource(new LoginAuthenticationDetailsSource());
        return filter;
    }

    @NotNull
    private MobileLoginAuthenticationProvider buildMobileLoginAuthenticationProvider(ApplicationContext context) {
        return new MobileLoginAuthenticationProvider(
                context.getBean(IamUserDetailsService.class),
                context.getBean(TokenIssuer.class),
                context.getBean(SmsCaptchaProvider.class)
        );
    }

    @NotNull
    private AccountLoginAuthenticationProvider buildAccountLoginAuthenticationProvider(ApplicationContext context) {
        return new AccountLoginAuthenticationProvider(
                context.getBean(IamUserDetailsService.class),
                context.getBean(TokenIssuer.class),
                context.getBean(PasswordEncoder.class)
        );
    }
} 