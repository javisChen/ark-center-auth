package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.lang.Assert;
import com.ark.center.auth.infra.authentication.common.Uris;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.List;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String LOGIN_URI = Uris.LOGIN;

    @SuppressWarnings("rawtypes")
    private final List<LoginAuthenticationConverter> loginAuthenticationConverters;

    @SuppressWarnings("rawtypes")
    public LoginAuthenticationFilter(List<LoginAuthenticationConverter> loginAuthenticationConverters) {
        super(new AntPathRequestMatcher(LOGIN_URI, HttpMethod.POST.name()));
        this.loginAuthenticationConverters = loginAuthenticationConverters;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (!request.getMethod().equals(HttpMethod.POST.name())
                && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        LoginMode mode = LoginMode.byCode(StringUtils.substringAfterLast(request.getRequestURI(), "/"));
        Authentication authentication = convertToAuthentication(request, mode);
        setDetails(request, authentication);
        return this.getAuthenticationManager().authenticate(authentication);
    }

    private Authentication convertToAuthentication(HttpServletRequest request, LoginMode loginMode) {
        Assert.notNull(loginMode, () -> new AuthenticationServiceException("不支持当前登录模式"));

        for (LoginAuthenticationConverter<?> converter : loginAuthenticationConverters) {
            if (converter.supports(loginMode)) {
                return converter.convert(request);
            }
        }

        log.error("Login mode [{}] not supported", loginMode);
        throw new AuthenticationServiceException("不支持当前登录模式");
    }

    protected void setDetails(HttpServletRequest request, Authentication authRequest) {
        if (authRequest instanceof AbstractAuthenticationToken authenticationToken) {
            authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
        }
    }

}
