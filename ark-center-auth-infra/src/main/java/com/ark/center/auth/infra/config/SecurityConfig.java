package com.ark.center.auth.infra.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
//        //省略HttpSecurity的配置
        httpSecurity
                .anonymous(configurer -> configurer
                        .key("213")
                        .disable()
                )
                .formLogin(configurer -> configurer.disable())
                .
        ;
        return httpSecurity.build();
    }

}
