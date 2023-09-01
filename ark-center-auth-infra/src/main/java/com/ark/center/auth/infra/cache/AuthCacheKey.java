package com.ark.center.auth.infra.cache;

public interface AuthCacheKey {

    /**
     * 短信登录验证码
     */
    String CACHE_KEY_USER_MOBILE_LOGIN_CODE = "user:login:mobile:%s:code";
}
