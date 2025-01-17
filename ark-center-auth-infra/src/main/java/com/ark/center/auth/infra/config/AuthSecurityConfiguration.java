package com.ark.center.auth.infra.config;

import com.ark.center.auth.infra.config.configurers.LoginSecurityConfigurer;
import com.ark.center.auth.infra.config.configurers.LogoutSecurityConfigurer;
import com.ark.center.auth.infra.authentication.context.AuthServerSecurityContextRepository;
import com.ark.component.cache.CacheService;
import com.ark.component.security.core.configurers.CommonHttpConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AuthSecurityConfiguration {

//    @Bean
//    public MessageSource messageSource() {
//        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
//        messageSource.setBasename("messages");
////        messageSource.setDefaultEncoding("UTF-8");
//        return messageSource;
//    }

    @Bean
    public SecurityContextRepository securityContextRepository(CacheService cacheService) {
        return new AuthServerSecurityContextRepository(cacheService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, SecurityContextRepository securityContextRepository) throws Exception {
        httpSecurity
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/v1/access/api/auth")
                                .permitAll()
                )
                .securityContext(c -> c.securityContextRepository(securityContextRepository))
                .with(new CommonHttpConfigurer(), configurer -> {})
                .with(new LogoutSecurityConfigurer(), configurer -> {})
                .with(new LoginSecurityConfigurer(), configurer -> {})
        ;

        return httpSecurity.build();
    }

}
