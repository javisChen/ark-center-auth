package com.ark.center.auth.infra.config;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.DefaultAuthenticationEntryPoint;
import com.ark.center.auth.infra.authentication.ApiAuthorizationManager;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.LoginUserDetailsService;
import com.ark.center.auth.infra.authentication.token.generator.JwtUserTokenGenerator;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.center.auth.infra.authentication.token.repository.RedisSecurityContextRepository;
import com.ark.component.cache.CacheService;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Arrays;
import java.util.List;

@Configuration
//@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
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
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> decisionVoters = Arrays.asList(
                new RoleVoter(),
                new AuthenticatedVoter(),
                new Jsr250Voter()
        );
        return new MyAccessDecisionManager(decisionVoters);
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
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager() {
        return new ApiAuthorizationManager(securityCoreProperties);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                           AuthenticationProvider authenticationProvider,
                                           LoginAuthenticationFilter loginAuthenticationFilter,
                                           AuthorizationManager<RequestAuthorizationContext> authorizationManager,
                                           SecurityContextRepository securityContextRepository) throws Exception {
        // 设置上下文存储
        httpSecurity.securityContext(configurer -> configurer.securityContextRepository(securityContextRepository));

        // 设置登录认证过滤器
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
                .anyRequest()
                    .access(authorizationManager)
                );

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
