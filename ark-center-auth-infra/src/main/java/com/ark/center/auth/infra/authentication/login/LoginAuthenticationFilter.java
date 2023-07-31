package com.ark.center.auth.infra.authentication.login;

import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.ark.center.auth.infra.authentication.SecurityConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "userName";

    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login/account",
            "POST");

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;

    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;

    private boolean postOnly = true;

    public LoginAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (this.postOnly && !request.getMethod().equals(HttpMethod.POST.name())
                && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        JSONObject loginParams;
        try {
            loginParams = JSON.parseObject(request.getInputStream());
            if (loginParams == null) {
                throw new AuthenticationServiceException("认证参数不合法");
            }
        } catch (Exception e) {
            throw new AuthenticationServiceException("认证参数不合法");
        }
        String username = loginParams.getString(usernameParameter);
        username = (username != null) ? username.trim() : "";
        String password =  loginParams.getString(passwordParameter);
        password = (password != null) ? password : "";
        password = DigestUtil.md5Hex(password) + SecurityConstants.PASSWORD_SALT;
        UsernamePasswordAuthenticationToken authRequest = LoginAuthenticationToken.unauthenticated(username,
                password);
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
