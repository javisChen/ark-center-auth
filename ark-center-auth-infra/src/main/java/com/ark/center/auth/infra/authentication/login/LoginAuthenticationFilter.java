package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.io.IoUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.client.authentication.command.BaseLoginAuthenticateRequest;
import com.ark.center.auth.client.authentication.common.AuthStrategy;
import com.ark.center.auth.infra.application.model.ApplicationAuthConfig;
import com.ark.center.auth.infra.application.service.ApplicationAuthConfigService;
import com.ark.center.auth.infra.authentication.common.CommonConst;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
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

    private static final String LOGIN_URI = CommonConst.URI_LOGIN;

    @SuppressWarnings("rawtypes")
    private final List<LoginAuthenticationConverter> loginAuthenticationConverters;
    private final ApplicationAuthConfigService applicationAuthConfigService;

    @SuppressWarnings("rawtypes")
    public LoginAuthenticationFilter(List<LoginAuthenticationConverter> loginAuthenticationConverters,
                                   ApplicationAuthConfigService applicationAuthConfigService) {
        super(new AntPathRequestMatcher(LOGIN_URI, HttpMethod.POST.name()));
        this.loginAuthenticationConverters = loginAuthenticationConverters;
        this.applicationAuthConfigService = applicationAuthConfigService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        validateRequest(request);
        // 读取请求体并保存
        String authenticateRequestBody = readAndSaveRequestBody(request);
        BaseLoginAuthenticateRequest authenticateRequest = parse(authenticateRequestBody);
        request.setAttribute(CommonConst.LOGIN_REQUEST_BODY_ATTR, authenticateRequestBody);
        request.setAttribute(CommonConst.BASE_LOGIN_REQUEST, authenticateRequest);

        // 验证应用系统配置
        validateApplicationConfig(request, authenticateRequest);

        // 获取认证策略并转换认证信息
        Authentication authentication = convertAuthentication(request, authenticateRequest);

        setDetails(request, authentication);
        return this.getAuthenticationManager().authenticate(authentication);
    }

    private void validateApplicationConfig(HttpServletRequest request, BaseLoginAuthenticateRequest authenticateRequest) {
        // 1. 验证应用系统是否存在
        ApplicationAuthConfig config = applicationAuthConfigService.getConfig(authenticateRequest.getAppCode());
        if (config == null) {
            log.error("Application [{}] not found", authenticateRequest.getAppCode());
            throw new AuthenticationServiceException("Application not found");
        }
        log.info("Application found: [{}]", config.getName());

        // 2. 验证认证策略是否允许
        AuthStrategy authStrategy = authenticateRequest.getAuthStrategy();
        if (!config.getAllowedAuthStrategies().contains(authStrategy)) {
            log.error("Authentication strategy [{}] not allowed for application [{}], allowed strategies are: [{}]", 
                    authStrategy, 
                    config.getName(),
                    config.getAllowedAuthStrategies());
            throw new AuthenticationServiceException("Authentication strategy not allowed for this application");
        }
        log.info("Authentication strategy [{}] allowed for application [{}]", authStrategy, config.getName());

        // 3. 保存应用配置到request
        request.setAttribute(CommonConst.APPLICATION_CONFIG, config);
    }

    @NotNull
    private BaseLoginAuthenticateRequest parse(String authenticateRequestBody) {
        return JSON.parseObject(authenticateRequestBody, BaseLoginAuthenticateRequest.class);
    }

    private void validateRequest(HttpServletRequest request) {
        if (!request.getMethod().equals(HttpMethod.POST.name())
                || !request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
    }

    private String readAndSaveRequestBody(HttpServletRequest request) {
        try {
            return IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to read request body: {}", e.getMessage(), e);
            throw new AuthenticationServiceException("Failed to read request body");
        }
    }

    private Authentication convertAuthentication(HttpServletRequest request, BaseLoginAuthenticateRequest authenticateRequest) {
        // 解析认证策略
        AuthStrategy authStrategy = authenticateRequest.getAuthStrategy();
        // 获取并使用对应转换器
        return loginAuthenticationConverters.stream()
                .filter(converter -> converter.supports(authStrategy))
                .findFirst()
                .map(converter -> converter.convert(request))
                .orElseThrow(() -> {
                    log.error("Authentication strategy [{}] not supported", authStrategy);
                    return new AuthenticationServiceException("Unsupported authentication strategy");
                });
    }

    protected void setDetails(HttpServletRequest request, Authentication authRequest) {
        if (authRequest instanceof AbstractAuthenticationToken authenticationToken) {
            Object details = this.authenticationDetailsSource.buildDetails(request);
            authenticationToken.setDetails(details);
        }
    }
}
