package com.ark.center.auth.infra.authentication.token.repository;

import cn.hutool.core.bean.BeanUtil;
import com.alibaba.fastjson2.JSONArray;
import com.ark.center.auth.infra.authentication.SecurityConstants;
import com.ark.center.auth.infra.authentication.common.RedisKeyConst;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationToken;
import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.component.cache.CacheService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
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

    private final List<Object> hashKeys = List.of(
            "userId",
            "userCode",
            "isSuperAdmin",
            "password",
            "username",
            "authorities",
            "accountNonExpired",
            "accountNonLocked",
            "credentialsNonExpired",
            "enabled");

    public RedisSecurityContextRepository(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

        LoginAuthenticationToken authentication = (LoginAuthenticationToken) context.getAuthentication();

        LoginUser loginUser = authentication.getLoginUser();

        String accessToken = authentication.getAccessToken();

        Map<String, Object> map = BeanUtil.beanToMap(loginUser, false, true);
        map.put("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

        cacheService.hashSet(createAccessTokenKey(accessToken), map, SecurityConstants.TOKEN_EXPIRES_SECONDS);

        cacheService.set(createUserIdKey(loginUser.getUserId()), accessToken, SecurityConstants.TOKEN_EXPIRES_SECONDS);
    }

    private SecurityContext readSecurityContextFromCache(HttpServletRequest request) {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        String accessToken = resolveToken(request);
        if (StringUtils.isNotEmpty(accessToken)) {
            List<Object> objects = cacheService.hashMultiGet(createAccessTokenKey(accessToken), hashKeys);
            if (CollectionUtils.isEmpty(objects)) {
                return context;
            }
            LoginUser loginUser = convert(objects);
            context.setAuthentication(new LoginAuthenticationToken(loginUser, accessToken));
        }
        return context;
    }

    private LoginUser convert(List<Object> objects) {
        LoginUser loginUser = new LoginUser();
        loginUser.setUserId(Long.parseLong(objects.get(0).toString()));
        loginUser.setUserCode(String.valueOf(objects.get(1)));
        loginUser.setIsSuperAdmin((Boolean) objects.get(2));
        loginUser.setUsername(String.valueOf(objects.get(4)));
        JSONArray authorities = (JSONArray) objects.get(5);
        loginUser.setAuthorities(authorities.stream()
                .map(item -> new SimpleGrantedAuthority((String) item))
                .collect(Collectors.toUnmodifiableSet()));
        loginUser.setAccountNonExpired((Boolean) objects.get(6));
        loginUser.setAccountNonLocked((Boolean) objects.get(7));
        loginUser.setCredentialsNonExpired((Boolean) objects.get(8));
        loginUser.setEnabled((Boolean) objects.get(9));
        return loginUser;
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
