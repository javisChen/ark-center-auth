package com.ark.center.auth.infra.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.formLogin(withDefaults());
//        // 资源权限控制
//        httpSecurity.authorizeHttpRequests(requests -> requests
//                .requestMatchers(EndpointRequest.to(HealthEndpoint.class))
//                    .permitAll()
//                .requestMatchers("/admin/test")
//                    .hasRole("ADMIN")
//                .anyRequest()
//                    .authenticated());
//
//
//        // 权限不足时的处理
//        httpSecurity.exceptionHandling(configurer -> configurer
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
//                        response.getWriter().write("access denied");
//                    }
//                })
//                .authenticationEntryPoint(new DefaultAuthenticationEntryPoint())
//        );
//        return httpSecurity.build();
//    }

}
