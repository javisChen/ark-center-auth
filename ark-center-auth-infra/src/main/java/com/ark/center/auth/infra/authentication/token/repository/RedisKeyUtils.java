package com.ark.center.auth.infra.authentication.token.repository;

import com.ark.center.auth.infra.authentication.common.RedisKeyConst;

public class RedisKeyUtils {


    public static String createAccessTokenKey(String accessToken) {
        return RedisKeyConst.LOGIN_USER_ACCESS_TOKEN_KEY_PREFIX + accessToken;
    }

    public static String createUserIdKey(Long userId) {
        return RedisKeyConst.LOGIN_USER_ID_KEY_PREFIX + userId;
    }
}
