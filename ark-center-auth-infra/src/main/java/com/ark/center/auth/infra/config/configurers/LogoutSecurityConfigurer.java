package com.ark.center.auth.infra.config.configurers;

import com.ark.center.auth.infra.authentication.common.Uris;
import com.ark.center.auth.infra.authentication.logout.AuthLogoutHandler;
import com.ark.component.cache.CacheService;
import com.ark.component.mq.integration.MessageTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Slf4j
public class LogoutSecurityConfigurer extends AbstractHttpConfigurer<LogoutSecurityConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);

        AuthLogoutHandler handler = new AuthLogoutHandler(
                context.getBean(CacheService.class)
        );

        httpSecurity.logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher(Uris.LOGOUT))
                .clearAuthentication(false)
                .logoutSuccessHandler(handler)
                .addLogoutHandler(handler)
        );
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

    }
} 