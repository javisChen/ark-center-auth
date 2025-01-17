package com.ark.center.auth.infra.authentication.context;

import cn.hutool.core.bean.BeanUtil;
import com.alibaba.fastjson2.JSONArray;
import com.ark.center.auth.infra.authentication.common.CacheKeyManager;
import com.ark.component.cache.CacheService;
import com.ark.component.security.base.user.AuthUser;
import com.ark.component.security.core.authentication.AuthenticatedToken;
import com.ark.component.security.core.common.SecurityConstants;
import com.ark.component.security.core.context.repository.AbstractSecurityContextRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * 认证服务的安全上下文存储库
 * 负责在Redis中存储和获取用户认证信息
 */
@Slf4j
public class AuthServerSecurityContextRepository extends AbstractSecurityContextRepository {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
    private final CacheService cacheService;

    /**
     * LoginUser对象的属性列表，用于Redis hash结构存储
     */
    private final List<Object> hashKeys = List.of(
            AuthUser.USER_ID,
            AuthUser.USER_CODE,
            AuthUser.IS_SUPER_ADMIN,
            "password",
            AuthUser.USERNAME,
            "authorities",
            "accountNonExpired",
            "accountNonLocked",
            "credentialsNonExpired",
            "enabled");

    public AuthServerSecurityContextRepository(CacheService cacheService) {
        Assert.notNull(cacheService, "CacheService must not be null");
        this.cacheService = cacheService;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = context.getAuthentication();

        if (authentication == null) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication is null, skip saving context");
            }
            return;
        }

        try {
            AuthenticatedToken authenticatedToken = (AuthenticatedToken) authentication;
            AuthUser authUser = authenticatedToken.getAuthUser();
            String accessToken = authenticatedToken.getAccessToken();

            if (log.isDebugEnabled()) {
                log.debug("Saving security context for user: {}", authUser.getUsername());
            }

            // 将LoginUser对象转换为Map并存储到Redis
            Map<String, Object> map = BeanUtil.beanToMap(authUser, false, true);
            map.put("authorities", authenticatedToken.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));

            cacheService.hMSet(CacheKeyManager.createAccessTokenKey(accessToken),
                    map, SecurityConstants.TOKEN_EXPIRES_SECONDS);

            // 存储用户ID到token的映射关系
            cacheService.set(CacheKeyManager.createUserIdKey(authUser.getUserId()),
                    accessToken, SecurityConstants.TOKEN_EXPIRES_SECONDS, TimeUnit.SECONDS);

            if (log.isDebugEnabled()) {
                log.debug("Successfully saved security context for user: {}", authUser.getUsername());
            }
        } catch (Exception e) {
            log.error("Failed to save security context", e);
            throw new IllegalStateException("Failed to save security context", e);
        }
    }


    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        return super.loadDeferredContext(request);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        String token = resolveToken(request);
        return cacheService.get(CacheKeyManager.createAccessTokenKey(token), AuthUser.class) != null;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return readSecurityContextFromCache(requestResponseHolder.getRequest());
    }

    private SecurityContext readSecurityContextFromCache(HttpServletRequest request) {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        String accessToken = resolveToken(request);
        
        if (StringUtils.isEmpty(accessToken)) {
            if (log.isDebugEnabled()) {
                log.debug("No access token found in request");
            }
            return context;
        }

        try {
            AuthUser authUser = loadAuthUserFromRedis(accessToken);
            if (authUser == null) {
                return context;
            }

            context.setAuthentication(AuthenticatedToken.authenticated(authUser, accessToken, "", 0L));

            if (log.isDebugEnabled()) {
                log.debug("Successfully loaded security context for user: {}", authUser.getUsername());
            }

            return context;
        } catch (Exception e) {
            log.error("Failed to load security context", e);
            return context;
        }
    }

    private AuthUser loadAuthUserFromRedis(String accessToken) {
        List<Object> values = cacheService.hMGet(CacheKeyManager.createAccessTokenKey(accessToken), hashKeys);
        
        if (!isValidValues(values)) {
            log.warn("No security context found in Redis for token: {}", accessToken);
            return null;
        }

        return assemble(values);
    }

    private boolean isValidValues(List<Object> values) {
        if (CollectionUtils.isEmpty(values)) {
            return false;
        }
        List<Object> nonNullValues = values.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        return CollectionUtils.isNotEmpty(nonNullValues);
    }

    protected String resolveToken(HttpServletRequest request) {
        return bearerTokenResolver.resolve(request);
    }

    private AuthUser assemble(List<Object> objects) {
        AuthUser authUser = new AuthUser();
        authUser.setUserId(Long.parseLong(objects.get(0).toString()));
        authUser.setUserCode(String.valueOf(objects.get(1)));
        authUser.setIsSuperAdmin((Boolean) objects.get(2));
        authUser.setUsername(String.valueOf(objects.get(4)));
        
        JSONArray authorities = (JSONArray) objects.get(5);
        authUser.setAuthorities(authorities.stream()
                .map(item -> new SimpleGrantedAuthority((String) item))
                .collect(Collectors.toUnmodifiableSet()));
                
        authUser.setAccountNonExpired((Boolean) objects.get(6));
        authUser.setAccountNonLocked((Boolean) objects.get(7));
        authUser.setCredentialsNonExpired((Boolean) objects.get(8));
        authUser.setEnabled((Boolean) objects.get(9));
        return authUser;
    }


} 