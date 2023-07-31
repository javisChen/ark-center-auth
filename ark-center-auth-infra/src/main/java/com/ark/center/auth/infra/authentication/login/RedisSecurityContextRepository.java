package com.ark.center.auth.infra.authentication.login;

import com.alibaba.fastjson2.JSONObject;
import com.ark.center.auth.infra.authentication.SecurityConstants;
import com.ark.center.auth.infra.authentication.common.RedisKeyConst;
import com.ark.center.auth.infra.authentication.login.token.cache.UserCacheInfo;
import com.ark.center.iam.client.permission.response.LoginUserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

public class RedisSecurityContextRepository implements SecurityContextRepository {

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return null;
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        return SecurityContextRepository.super.loadDeferredContext(request);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String accessToken = generateAccessToken(userContext);
        saveCache(createAccessTokenKey(accessToken), JSONObject.toJSONString(userContext), SecurityConstants.TOKEN_EXPIRES_SECONDS);
        saveCache(createUserIdKey(userContext.getUserId()), accessToken, SecurityConstants.TOKEN_EXPIRES_SECONDS);
        return new UserCacheInfo(accessToken, SecurityConstants.TOKEN_EXPIRES_SECONDS);
    }

    private String createAccessTokenKey(String accessToken) {
        return RedisKeyConst.LOGIN_USER_ACCESS_TOKEN_KEY_PREFIX + accessToken;
    }

    private String createUserIdKey(Long userId) {
        return RedisKeyConst.LOGIN_USER_ID_KEY_PREFIX + userId;
    }


    private String generateAccessToken(LoginUserResponse userContext) {
        String accessToken;
        // 防止重复
        do {
            accessToken = userTokenGenerator.generate(userContext);
        } while (!checkAccessTokenIsNotExists(accessToken));
        return accessToken;
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }
}
