package com.ark.center.auth.infra.authentication.token.generator;


import com.ark.center.auth.infra.authentication.token.UserToken;
import com.ark.component.security.base.user.LoginUser;

/**
 * Token生成器接口
 */
public interface UserTokenGenerator {
    /**
     * 生成用户Token
     */
    UserToken generate(LoginUser loginUser);
}
