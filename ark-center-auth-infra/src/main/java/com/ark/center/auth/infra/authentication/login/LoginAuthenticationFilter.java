package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.io.IoUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.client.login.constant.LoginMode;
import com.ark.center.auth.infra.authentication.common.Uris;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String LOGIN_URI = Uris.LOGIN;
    public static final String LOGIN_REQUEST_BODY_ATTR = "loginRequestBody";

    @SuppressWarnings("rawtypes")
    private final List<LoginAuthenticationConverter> loginAuthenticationConverters;

    @SuppressWarnings("rawtypes")
    public LoginAuthenticationFilter(List<LoginAuthenticationConverter> loginAuthenticationConverters) {
        super(new AntPathRequestMatcher(LOGIN_URI, HttpMethod.POST.name()));
        this.loginAuthenticationConverters = loginAuthenticationConverters;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        validateRequest(request);
        // 读取请求体并保存
        String requestBody = readAndSaveRequestBody(request);
        // 获取登录模式并转换认证信息
        Authentication authentication = convertAuthentication(requestBody, request);
        
        setDetails(request, authentication);
        return this.getAuthenticationManager().authenticate(authentication);
    }

    private void validateRequest(HttpServletRequest request) {
        if (!request.getMethod().equals(HttpMethod.POST.name())
                || !request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
    }

    private String readAndSaveRequestBody(HttpServletRequest request) {
        try {
            String requestBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
            // 保存请求体供后续使用
            request.setAttribute(LOGIN_REQUEST_BODY_ATTR, requestBody);
            return requestBody;
        } catch (Exception e) {
            log.error("Failed to read request body: {}", e.getMessage(), e);
            throw new AuthenticationServiceException("Failed to read request body");
        }
    }

    private Authentication convertAuthentication(String requestBody, HttpServletRequest request) {
        // 解析登录模式
        LoginMode loginMode = parseLoginMode(requestBody);
        // 获取并使用对应转换器
        return loginAuthenticationConverters.stream()
                .filter(converter -> converter.supports(loginMode))
                .findFirst()
                .map(converter -> converter.convert(request))
                .orElseThrow(() -> {
                    log.error("Login mode [{}] not supported", loginMode);
                    return new AuthenticationServiceException("Unsupported login mode");
                });
    }

    private LoginMode parseLoginMode(String requestBody) {
        try {
            BaseLoginAuthenticateRequest baseCommand = JSON.parseObject(requestBody, BaseLoginAuthenticateRequest.class);
            if (baseCommand == null || baseCommand.getLoginMode() == null) {
                throw new AuthenticationServiceException("Login mode cannot be null");
            }
            return baseCommand.getLoginMode();
        } catch (Exception e) {
            log.error("Failed to parse login mode: {}", e.getMessage(), e);
            throw new AuthenticationServiceException("Invalid login parameters");
        }
    }

    protected void setDetails(HttpServletRequest request, Authentication authRequest) {
        if (authRequest instanceof AbstractAuthenticationToken authenticationToken) {
            authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
        }
    }
}
