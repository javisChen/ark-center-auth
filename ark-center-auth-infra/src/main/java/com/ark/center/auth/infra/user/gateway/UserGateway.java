package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.component.security.base.authentication.AuthUser;

import java.util.List;

/**
 * 用户远程服务调用接口
 */
public interface UserGateway {

    /**
     * 根据手机号获取用户信息
     */
    AuthUser retrieveUserByMobile(String mobile);

    /**
     * 根据用户名获取用户信息
     */
    AuthUser retrieveUserByUsername(String username);

    /**
     * 远程获取用户的API权限列表
     */
    List<AuthUserApiPermission> queryUserApiPermissions(Long userId);
}
