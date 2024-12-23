package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.util.ClassUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.client.login.constant.LoginMode;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import static com.ark.center.auth.infra.authentication.login.LoginAuthenticationFilter.LOGIN_REQUEST_BODY_ATTR;

/**
 * 登录认证请求转换器抽象类
 * 负责将HTTP请求转换为对应的认证对象
 *
 * @param <T> 登录请求参数类型
 * @author JC
 */
@Slf4j
public abstract class LoginAuthenticationConverter<T extends BaseLoginAuthenticateRequest>
        extends RequestConverter<T>
        implements AuthenticationConverter, InitializingBean {

    private Class<T> clazz;

    @Override
    @SuppressWarnings("unchecked")
    public void afterPropertiesSet() {
        this.clazz = (Class<T>) ClassUtil.getTypeArgument(getClass());;
    }



    @Override
    public Authentication convert(HttpServletRequest request) {
        String cachedRequest = (String) request.getAttribute(LOGIN_REQUEST_BODY_ATTR);
        return doConvert(JSON.to(clazz, cachedRequest));
    }

    /**
     * 读取并校验认证请求参数
     */
    @NotNull
    private T readRequest(HttpServletRequest request) {
        T authenticateRequest;
        try {
            authenticateRequest = readFromRequest(request);
        } catch (Exception e) {
            log.error("Failed to read authentication parameters:", e);
            throw new AuthenticationServiceException("Invalid authentication parameters");
        }
        if (authenticateRequest == null) {
            log.error("Authentication request parameters cannot be null");
            throw new AuthenticationServiceException("Invalid authentication parameters");
        }
        return authenticateRequest;
    }

    /**
     * 将认证请求参数转换为认证对象
     */
    protected abstract Authentication doConvert(T authenticateRequest);

    /**
     * 判断是否支持指定的登录模式
     */
    protected abstract boolean supports(LoginMode loginMode);
}
