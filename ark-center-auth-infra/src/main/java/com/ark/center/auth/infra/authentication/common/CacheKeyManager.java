package com.ark.center.auth.infra.authentication.common;

import com.ark.component.security.core.common.SecurityConstants;

public class CacheKeyManager {

    public static String createAccessTokenKey(String accessToken) {
        return SecurityConstants.CACHE_KEY_PREFIX_LOGIN_USER_ACCESS_TOKEN + accessToken;
    }

    public static String createUserIdKey(Long userId) {
        return SecurityConstants.CACHE_KEY_PREFIX_LOGIN_USER_ID + userId;
    }

}
