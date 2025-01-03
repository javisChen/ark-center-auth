package com.ark.center.auth.infra.authentication;

import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.component.common.util.spring.SpringUtils;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import com.ark.component.security.core.exception.AuthException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Slf4j
public class AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String requestUri = request.getRequestURI();
        String remoteIp = request.getRemoteAddr();
        
        log.error("Authentication failed - URI: {}, IP: {}, Error: {}", 
                requestUri, remoteIp, exception.getMessage(), exception);
        
        String applicationName = SpringUtils.getApplicationName();
        int httpStatusCode = HttpStatus.BAD_REQUEST.value();
        
        // 处理自定义认证异常
        if (exception instanceof AuthException authException) {
            httpStatusCode = authException.getHttpStatusCode();
        }
        
        ServerResponse responseBody = SingleResponse.error(
                applicationName, 
                String.valueOf(httpStatusCode), 
                exception.getMessage()
        );
        
        ResponseUtils.write(responseBody, response, httpStatusCode);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String username = authentication.getName();
        String requestUri = request.getRequestURI();
        String remoteIp = request.getRemoteAddr();
        
        log.info("Authentication success - User: {}, URI: {}, IP: {}", 
                username, requestUri, remoteIp);
                
        ServerResponse responseBody = SingleResponse.ok();
        ResponseUtils.write(responseBody, response, HttpStatus.OK.value());
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        // 调用标准的成功处理方法
        onAuthenticationSuccess(request, response, authentication);
    }
}
