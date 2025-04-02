package com.ark.center.auth.infra.user.gateway;

import com.ark.component.security.base.authentication.AuthUser;

/**
 * 用户远程服务调用接口
 */
public interface MemberGateway {

    /**
     * 根据手机号获取用户信息
     */
    AuthUser retrieveUserByMobile(String mobile);

    /**
     * 根据用户名获取用户信息
     */
    AuthUser retrieveUserByUsername(String username);

    /**
     * 注册会员
     */
    AuthUser register(String mobile);

}
