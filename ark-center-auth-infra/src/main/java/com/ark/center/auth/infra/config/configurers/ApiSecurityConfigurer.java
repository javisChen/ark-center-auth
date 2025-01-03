package com.ark.center.auth.infra.config.configurers;

import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import com.ark.center.auth.infra.api.service.ApiAccessControlService;
import com.ark.center.auth.infra.user.service.UserPermissionService;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationFilter;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationHandler;
import com.ark.center.auth.infra.authentication.api.ApiAccessAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Slf4j
@RequiredArgsConstructor
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
            context.getBean(ApiAccessControlService.class),
            context.getBean(UserPermissionService.class)
        );
        
        http.addFilterBefore(filter, LoginAuthenticationFilter.class)
            .authenticationProvider(provider);
    }
} 