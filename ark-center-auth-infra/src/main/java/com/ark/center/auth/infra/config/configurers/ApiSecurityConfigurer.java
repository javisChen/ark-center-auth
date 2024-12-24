package com.ark.center.auth.infra.config.configurers;

import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationFilter;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationHandler;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationProvider;
import com.ark.center.auth.infra.authentication.cache.ApiCache;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Slf4j
public class ApiSecurityConfigurer extends AbstractHttpConfigurer<ApiSecurityConfigurer, HttpSecurity> {
    
    @Override
    public void configure(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        
        ApiAccessAuthenticationHandler authenticationHandler = new ApiAccessAuthenticationHandler();
        ApiAccessAuthenticationFilter filter = new ApiAccessAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setAuthenticationManager(authenticationManager);
        
        ApiAccessAuthenticationProvider provider = new ApiAccessAuthenticationProvider(
            context.getBean(ApiCache.class),
            context.getBean(UserPermissionService.class)
        );
        
        http.addFilterBefore(filter, LoginAuthenticationFilter.class)
            .authenticationProvider(provider);
    }
} 