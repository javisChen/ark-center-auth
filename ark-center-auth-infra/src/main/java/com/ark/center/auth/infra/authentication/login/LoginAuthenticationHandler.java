package com.ark.center.auth.infra.authentication.login;

import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.component.common.util.spring.SpringUtils;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import com.ark.component.security.core.authentication.LoginAuthenticationToken;
import com.ark.component.security.core.authentication.exception.AuthException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * 登录认证处理器
 */
@Slf4j
public class LoginAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        log.error("Authentication Failure", exception);
        String applicationName = SpringUtils.getApplicationName();
        int httpStatusCode = org.springframework.http.HttpStatus.BAD_REQUEST.value();
        ServerResponse responseBody = SingleResponse.error(applicationName, String.valueOf(httpStatusCode), exception.getMessage());

        if (exception instanceof AuthException authException) {
            httpStatusCode = authException.getHttpStatusCode();
        }

        responseBody.setMsg(exception.getMessage());
        ResponseUtils.write(responseBody, response, httpStatusCode);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        writeSuccess(response, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        writeSuccess(response, authentication);
    }

    private void writeSuccess(HttpServletResponse response, Authentication authentication) throws IOException {
        LoginAuthenticationToken authenticationToken = (LoginAuthenticationToken) authentication;
        SingleResponse<LoginAuthenticateResponse> serverResponse = SingleResponse.ok(new LoginAuthenticateResponse(authenticationToken.getAccessToken()));
        ResponseUtils.write(serverResponse, response, HttpStatus.SC_OK);
    }

}
