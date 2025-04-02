package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.component.security.base.authentication.AuthUser;
import org.springframework.security.core.Authentication;

import java.util.Set;

/**
 * 用户源提供者接口
 */
public interface UserSourceProvider {

    /**
     * 根据用户名获取用户信息
     */
    AuthUser retrieveUserByUsername(String username, Authentication authentication);

    /**
     * 根据手机号获取用户信息
     */
    AuthUser retrieveUserByMobile(String mobile, Authentication authentication);

    /**
     * 获取支持的应用编码集合
     */
    Set<AppCode> getSupportedAppCodes();

    /**
     * 是否支持该应用
     */
    default boolean supports(AppCode appCode) {
        return getSupportedAppCodes().contains(appCode);
    }
} 