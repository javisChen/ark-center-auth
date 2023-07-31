package com.ark.center.auth.infra.authentication.login;

import com.alibaba.fastjson2.JSON;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.entity.ContentType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 登录认证处理器
 */
public class LoginAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        ServerResponse serverResponse = SingleResponse.error("auth", "400", exception.getMessage());
        doWrite(JSON.toJSONBytes(serverResponse), response, HttpServletResponse.SC_BAD_REQUEST);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        writeSuccess(request, response, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        writeSuccess(request, response, authentication);
    }

    private void writeSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        LoginAuthenticationToken authenticationToken = (LoginAuthenticationToken) authentication;
        SingleResponse<AuthLoginDTO> serverResponse = SingleResponse.ok(new AuthLoginDTO(authenticationToken.getAccessToken()));
        doWrite(JSON.toJSONBytes(serverResponse), response, HttpServletResponse.SC_OK);
    }

    private void doWrite(byte[] body, HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
        response.setContentType(ContentType.APPLICATION_JSON.getMimeType());
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
