package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.io.IoUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.infra.authentication.SecurityConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login/account",
            "POST");

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();


    public LoginAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        Authentication authentication = securityContextHolderStrategy.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
//            return authentication;
        }
        if (!request.getMethod().equals(HttpMethod.POST.name())
                && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        LoginAuthenticateRequest authenticateRequest = readFromRequest(request);
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(authenticateRequest.getUsername(), authenticateRequest.getPassword());
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private LoginAuthenticateRequest readFromRequest(HttpServletRequest request) {
        LoginAuthenticateRequest authenticateRequest;
        try {
            String reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
            authenticateRequest = JSON.to(LoginAuthenticateRequest.class, reqBody);
        } catch (Exception e) {
            log.error("读取认证参数失败", e);
            throw new AuthenticationServiceException("认证参数不合法");
        }
        if (authenticateRequest == null) {
            throw new AuthenticationServiceException("认证参数不合法");
        }
        authenticateRequest.setPassword(DigestUtil.md5Hex(authenticateRequest.getPassword()) + SecurityConstants.PASSWORD_SALT);
        return authenticateRequest;
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
