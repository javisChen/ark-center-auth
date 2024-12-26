package com.ark.center.auth.infra.config;

import com.ark.center.auth.infra.authentication.token.generator.JwtUserTokenGenerator;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.center.auth.infra.config.configurers.ApiSecurityConfigurer;
import com.ark.center.auth.infra.config.configurers.LoginSecurityConfigurer;
import com.ark.center.auth.infra.config.configurers.LogoutSecurityConfigurer;
import com.ark.component.security.core.configurers.CommonHttpConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AuthSecurityConfiguration {

    @Bean
    public UserTokenGenerator userTokenGenerator(JwtEncoder jwtEncoder) {
        return new JwtUserTokenGenerator(jwtEncoder);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/captcha/**")
//                                .permitAll()
//                )
                .with(new CommonHttpConfigurer(), configurer -> {})
                .with(new LogoutSecurityConfigurer(), configurer -> {})
                .with(new LoginSecurityConfigurer(), configurer -> {})
                .with(new ApiSecurityConfigurer(), configurer -> {});

        return httpSecurity.build();
    }

}
