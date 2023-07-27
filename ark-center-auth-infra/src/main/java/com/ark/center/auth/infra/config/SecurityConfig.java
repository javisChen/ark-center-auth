package com.ark.center.auth.infra.config;

import com.ark.center.auth.infra.DefaultAuthenticationEntryPoint;
import com.ark.center.auth.infra.authentication.DefaultUserDetailsService;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationHandler;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        return new DefaultUserDetailsService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter();
        LoginAuthenticationHandler authenticationHandler = new LoginAuthenticationHandler();
        loginAuthenticationFilter.setAuthenticationSuccessHandler(authenticationHandler);
        loginAuthenticationFilter.setAuthenticationFailureHandler(authenticationHandler);
        loginAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        httpSecurity.addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // 使用无状态Session
        httpSecurity.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity.formLogin(Customizer.withDefaults());

        httpSecurity.oauth2ResourceServer(configurer -> {
            configurer.jwt(new Customizer<OAuth2ResourceServerConfigurer<org.springframework.security.config.annotation.web.builders.HttpSecurity>.JwtConfigurer>() {
                        @Override
                        public void customize(OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
                            jwtConfigurer.decoder(new NimbusJwtDecoder())
                                    .jwtAuthenticationConverter()
                        }
                    })
        });

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
