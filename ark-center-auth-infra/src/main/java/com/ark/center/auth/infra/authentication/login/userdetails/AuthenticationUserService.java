package com.ark.center.auth.infra.authentication.login.userdetails;

import com.ark.component.security.base.authentication.AuthUser;
import org.springframework.security.core.Authentication;

/**
 * 认证用户服务
 */
public interface AuthenticationUserService {

    /**
     * 根据用户名获取用户信息
     */
    AuthUser loadUserByUsername(String username, Authentication authentication);

    /**
     * 根据手机号获取用户信息
     */
    AuthUser loadUserByMobile(String mobile, Authentication authentication);
} 