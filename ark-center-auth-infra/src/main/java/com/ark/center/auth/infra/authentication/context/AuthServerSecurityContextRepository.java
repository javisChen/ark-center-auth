package com.ark.center.auth.infra.authentication.context;

import com.alibaba.fastjson2.JSONArray;
import com.ark.center.auth.infra.authentication.common.CacheKeyManager;
import com.ark.center.auth.infra.authentication.LoginAuthenticationDetails;
import com.ark.center.auth.infra.application.model.ApplicationAuthConfig;
import com.ark.component.cache.CacheService;
import com.ark.component.security.base.authentication.AuthUser;
import com.ark.component.security.base.authentication.Token;
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
import java.util.HashMap;

/**
 * 认证服务的安全上下文存储库
 * 负责在Redis中存储和获取用户认证信息
 */
@Slf4j
public class AuthServerSecurityContextRepository extends AbstractSecurityContextRepository {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
    private final CacheService cacheService;
    private final List<Object> hashKeys = AuthenticatedCacheKeys.getKeys();

    public AuthServerSecurityContextRepository(CacheService cacheService) {
        Assert.notNull(cacheService, "CacheService must not be null");
        this.cacheService = cacheService;
    }

    private Map<String, Object> buildCacheMap(AuthenticatedToken authenticatedToken) {
        AuthUser authUser = authenticatedToken.getAuthUser();
        Map<String, Object> map = new HashMap<>(16);
        
        // 基本用户信息
        map.put(AuthenticatedCacheKeys.USER_ID.getValue().toString(), authUser.getUserId());
        map.put(AuthenticatedCacheKeys.USER_CODE.getValue().toString(), authUser.getUserCode());
        map.put(AuthenticatedCacheKeys.IS_SUPER_ADMIN.getValue().toString(), authUser.getIsSuperAdmin());
        map.put(AuthenticatedCacheKeys.USERNAME.getValue().toString(), authUser.getUsername());
        
        // 权限信息
        map.put(AuthenticatedCacheKeys.AUTHORITIES.getValue().toString(), authenticatedToken.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        
        // 账户状态
        map.put(AuthenticatedCacheKeys.ACCOUNT_NON_EXPIRED.getValue().toString(), authUser.isAccountNonExpired());
        map.put(AuthenticatedCacheKeys.ACCOUNT_NON_LOCKED.getValue().toString(), authUser.isAccountNonLocked());
        map.put(AuthenticatedCacheKeys.CREDENTIALS_NON_EXPIRED.getValue().toString(), authUser.isCredentialsNonExpired());
        map.put(AuthenticatedCacheKeys.ENABLED.getValue().toString(), authUser.isEnabled());
        
        // 应用信息
        LoginAuthenticationDetails details = (LoginAuthenticationDetails) authenticatedToken.getDetails();
        ApplicationAuthConfig config = details.getApplicationAuthConfig();
        map.put(AuthenticatedCacheKeys.APP_CODE.getValue().toString(), config.getCode());
        map.put(AuthenticatedCacheKeys.APP_TYPE.getValue().toString(), config.getAppType());

        return map;
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
            String accessToken = authenticatedToken.getToken().getAccessToken();

            if (log.isDebugEnabled()) {
                log.debug("Saving security context for user: {}", authUser.getUsername());
            }

            Map<String, Object> map = buildCacheMap(authenticatedToken);
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
            AuthenticatedToken authenticatedToken = loadAuthenticatedTokenFromRedis(accessToken);
            if (authenticatedToken == null) {
                return context;
            }

            context.setAuthentication(authenticatedToken);

            if (log.isDebugEnabled()) {
                log.debug("Successfully loaded security context for user: {}", authenticatedToken.getAuthUser().getUsername());
            }

            return context;
        } catch (Exception e) {
            log.error("Failed to load security context", e);
            return context;
        }
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
        authUser.setUserId(Long.parseLong(objects.get(AuthenticatedCacheKeys.USER_ID.getIndex()).toString()));
        authUser.setUserCode(String.valueOf(objects.get(AuthenticatedCacheKeys.USER_CODE.getIndex())));
        authUser.setIsSuperAdmin((Boolean) objects.get(AuthenticatedCacheKeys.IS_SUPER_ADMIN.getIndex()));
        authUser.setUsername(String.valueOf(objects.get(AuthenticatedCacheKeys.USERNAME.getIndex())));
        
        JSONArray authorities = (JSONArray) objects.get(AuthenticatedCacheKeys.AUTHORITIES.getIndex());
        authUser.setAuthorities(authorities.stream()
                .map(item -> new SimpleGrantedAuthority((String) item))
                .collect(Collectors.toUnmodifiableSet()));
                
        authUser.setAccountNonExpired((Boolean) objects.get(AuthenticatedCacheKeys.ACCOUNT_NON_EXPIRED.getIndex()));
        authUser.setAccountNonLocked((Boolean) objects.get(AuthenticatedCacheKeys.ACCOUNT_NON_LOCKED.getIndex()));
        authUser.setCredentialsNonExpired((Boolean) objects.get(AuthenticatedCacheKeys.CREDENTIALS_NON_EXPIRED.getIndex()));
        authUser.setEnabled((Boolean) objects.get(AuthenticatedCacheKeys.ENABLED.getIndex()));
        return authUser;
    }

    private Token assembleToken(String accessToken, List<Object> values) {
        return Token.of(
            accessToken,
            "",  // 从Redis中恢复时不需要刷新令牌
            SecurityConstants.TOKEN_EXPIRES_SECONDS,
            String.valueOf(values.get(AuthenticatedCacheKeys.APP_CODE.getIndex())),
            String.valueOf(values.get(AuthenticatedCacheKeys.APP_TYPE.getIndex()))
        );
    }

    private AuthenticatedToken loadAuthenticatedTokenFromRedis(String accessToken) {
        List<Object> values = cacheService.hMGet(CacheKeyManager.createAccessTokenKey(accessToken), hashKeys);
        
        if (!isValidValues(values)) {
            log.warn("No security context found in Redis for token: {}", accessToken);
            return null;
        }

        // 组装用户信息
        AuthUser authUser = assemble(values);
        
        // 组装令牌信息
        Token token = assembleToken(accessToken, values);
        
        return AuthenticatedToken.authenticated(authUser, token);
    }

} 