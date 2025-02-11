package com.ark.center.auth.infra.user.repository;

import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.cache.UserPermissionRedisCache;
import com.ark.center.auth.infra.user.gateway.UserGateway;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * 用户权限数据管理
 * 负责用户权限数据的本地缓存和Redis缓存管理
 */
@Slf4j
@Component
public class UserPermissionRepository implements InitializingBean {

    private final UserGateway userGateway;
    private final UserPermissionRedisCache redisCache;
    private LoadingCache<Long, Map<Long, AuthUserApiPermission>> localCache;

    private static final long LOCAL_CACHE_EXPIRE_MINUTES = 30;
    private static final long LOCAL_CACHE_MAX_SIZE = 10000;

    public UserPermissionRepository(UserGateway userGateway, UserPermissionRedisCache redisCache) {
        this.userGateway = userGateway;
        this.redisCache = redisCache;
        initLocalCache();
    }

    private void initLocalCache() {

        this.localCache = Caffeine.newBuilder()
                .expireAfterWrite(LOCAL_CACHE_EXPIRE_MINUTES, TimeUnit.MINUTES)
                .expireAfterAccess(LOCAL_CACHE_EXPIRE_MINUTES * 2, TimeUnit.MINUTES)
                .maximumSize(LOCAL_CACHE_MAX_SIZE)
                .initialCapacity(1000)
                .recordStats()
                .evictionListener((userId, permissions, cause) -> {
                    if (log.isDebugEnabled()) {
                        log.debug("User permission cache evicted - userId: {}, cause: {}", userId, cause);
                    }
                })
                .build(userId -> {
                    List<AuthUserApiPermission> permissions = redisCache.loadPermissions(userId)
                            .orElseGet(() -> {
                                if (log.isDebugEnabled()) {
                                    log.debug("Redis cache miss for user {}, loading from remote", userId);
                                }
                                List<AuthUserApiPermission> remotePermissions = userGateway.queryUserApiPermissions(userId);
                                redisCache.savePermissions(userId, remotePermissions);
                                return remotePermissions;
                            });

                    return permissions.stream()
                            .collect(Collectors.toMap(
                                    AuthUserApiPermission::getApiId,
                                    permission -> permission,
                                    (existing, replacement) -> existing
                            ));
                });
    }

    @Override
    public void afterPropertiesSet() {
        // 初始化时不需要预加载数据，采用懒加载策略
    }

    /**
     * 获取用户的API权限列表
     */
    public void getUserApiPermissions(Long userId) {
        localCache.get(userId);
    }

    /**
     * 根据API ID获取用户的API权限
     * 使用O(1)的查询性能
     */
    public AuthUserApiPermission getUserApiPermission(Long userId, Long apiId) {
        Map<Long, AuthUserApiPermission> userApiMap = localCache.get(userId);
        return userApiMap.get(apiId);
    }

    /**
     * 刷新用户的权限缓存
     */
    public void refreshUserPermissions(Long userId) {
        log.debug("Refreshing permissions cache for user {}", userId);
        removeUserPermissions(userId);
        getUserApiPermissions(userId);
    }

    /**
     * 移除用户的权限缓存
     */
    public void removeUserPermissions(Long userId) {
        log.debug("Removing permissions cache for user {}", userId);
        redisCache.removePermissions(userId);
        localCache.invalidate(userId);
    }
} 