package com.ark.center.auth.infra.authentication.token.cache;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.ReflectUtil;
import com.ark.center.auth.infra.authentication.SecurityConstants;
import com.ark.center.auth.infra.authentication.common.RedisKeyConst;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationToken;
import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.component.cache.CacheService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

/**
 * RedisToken管理器
 */
@Slf4j
@Component
public class RedisSecurityContextRepository extends AbstractSecurityContextRepository {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
    private final CacheService cacheService;

    public RedisSecurityContextRepository(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

        LoginAuthenticationToken authentication = (LoginAuthenticationToken) context.getAuthentication();

        LoginUser loginUser = authentication.getLoginUser();

        String accessToken = authentication.getAccessToken();

        Map<String, Object> map = BeanUtil.beanToMap(loginUser, false, false);

        cacheService.hashSet(createAccessTokenKey(accessToken), map, SecurityConstants.TOKEN_EXPIRES_SECONDS);

        cacheService.set(createUserIdKey(loginUser.getUserId()), accessToken, SecurityConstants.TOKEN_EXPIRES_SECONDS);
    }

    private SecurityContext readSecurityContextFromCache(HttpServletRequest request) {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        String accessToken = resolveToken(request);
        if (StringUtils.isNotEmpty(accessToken)) {
            Set<Object> hashKeys = Arrays.stream(ReflectUtil.getFields(LoginUser.class))
                    .map(Field::getName)
                    .collect(Collectors.toUnmodifiableSet());
            List<Object> objects = cacheService.hashMultiGet(createAccessTokenKey(accessToken), hashKeys);
            LoginUser loginUser = (LoginUser) objects;
            context.setAuthentication(new LoginAuthenticationToken(loginUser, accessToken, Collections.emptySet()));
        }
        return context;
    }

    protected String resolveToken(HttpServletRequest request) {
        return bearerTokenResolver.resolve(request);
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return readSecurityContextFromCache(requestResponseHolder.getRequest());
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        String token = resolveToken(request);
        return cacheService.get(createAccessTokenKey(token), LoginUser.class) != null;
    }


    private String createAccessTokenKey(String accessToken) {
        return RedisKeyConst.LOGIN_USER_ACCESS_TOKEN_KEY_PREFIX + accessToken;
    }

    private String createUserIdKey(Long userId) {
        return RedisKeyConst.LOGIN_USER_ID_KEY_PREFIX + userId;
    }

}
