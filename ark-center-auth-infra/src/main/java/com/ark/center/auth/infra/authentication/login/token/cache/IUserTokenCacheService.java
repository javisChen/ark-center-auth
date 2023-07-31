package com.ark.center.auth.infra.authentication.login.token.cache;


import com.ark.center.iam.client.permission.response.LoginUserResponse;

/**
 * 用户Token缓存
 */
public interface IUserTokenCacheService {

    UserCacheInfo save(LoginUserResponse value);

    void remove(String accessToken);

    void remove(Long userId);

    LoginUserResponse get(String accessToken);

}
