package com.ark.center.auth.infra.authentication.login;

import com.ark.center.auth.infra.authentication.AuthenticationHandler;
import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.component.dto.SingleResponse;
import com.ark.component.security.core.authentication.AuthenticatedToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.core.Authentication;

import java.io.IOException;

/**
 * 登录认证处理器
 */
@Slf4j
public class LoginAuthenticationHandler extends AuthenticationHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        writeSuccess(response, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        writeSuccess(response, authentication);
    }

    private void writeSuccess(HttpServletResponse response, Authentication authentication) throws IOException {
        AuthenticatedToken authenticationToken = (AuthenticatedToken) authentication;
        LoginAuthenticateResponse authenticateResponse = new LoginAuthenticateResponse(authenticationToken.getToken().getAccessToken());
        SingleResponse<LoginAuthenticateResponse> serverResponse = SingleResponse.ok(authenticateResponse);
        ResponseUtils.write(serverResponse, response, HttpStatus.SC_OK);
    }

}
