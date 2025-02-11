package com.ark.center.auth.infra.authentication.login;

import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.client.authentication.command.BaseLoginAuthenticateRequest;
import com.ark.center.auth.client.authentication.constant.AuthStrategy;
import com.ark.center.auth.infra.authentication.common.CommonConst;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;


/**
 * 登录认证请求转换器抽象类
 * 负责将HTTP请求转换为对应的认证对象
 *
 * @param <T> 登录请求参数类型
 * @author JC
 */
@Slf4j
public abstract class LoginAuthenticationConverter<T extends BaseLoginAuthenticateRequest> extends RequestConverter<T>
        implements AuthenticationConverter {


    @Override
    public Authentication convert(HttpServletRequest request) {
        String cachedRequest = (String) request.getAttribute(CommonConst.LOGIN_REQUEST_BODY_ATTR);
        T authenticateRequest = JSON.to(clazz, cachedRequest);
        return doConvert(authenticateRequest);
    }

    /**
     * 将认证请求参数转换为认证对象
     */
    protected abstract Authentication doConvert(T authenticateRequest);

    /**
     * 判断是否支持指定的认证策略
     */
    protected abstract boolean supports(AuthStrategy authStrategy);
}
