package com.ark.center.auth.infra.user.cache;

import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.component.cache.CacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * 用户权限Redis缓存管理
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserPermissionRedisCache {

    private static final String CACHE_KEY_PATTERN = "user:%d:api:permissions";
    private static final Long CACHE_TTL_HOURS = 12L;

    private final CacheService cacheService;

    /**
     * 保存用户权限到Redis缓存
     */
    public void savePermissions(Long userId, List<AuthUserApiPermission> permissions) {
        try {
            String key = formatKey(userId);
            cacheService.set(key, JSON.toJSONString(permissions), CACHE_TTL_HOURS, TimeUnit.HOURS);
            log.debug("Successfully saved {} permissions to Redis cache for user {}", permissions.size(), userId);
        } catch (Exception e) {
            log.error("Failed to save permissions to Redis for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to save permissions to Redis", e);
        }
    }

    /**
     * 从Redis缓存加载用户权限
     */
    public Optional<List<AuthUserApiPermission>> loadPermissions(Long userId) {
        try {
            String key = formatKey(userId);
            String value = cacheService.get(key, String.class);
            if (value == null) {
                log.debug("No permissions found in Redis cache for user {}", userId);
                return Optional.empty();
            }

            List<AuthUserApiPermission> permissions = JSON.parseArray(value, AuthUserApiPermission.class);
            log.debug("Successfully loaded {} permissions from Redis cache for user {}", permissions.size(), userId);
            return Optional.of(permissions);
        } catch (Exception e) {
            log.error("Failed to load permissions from Redis for user {}: {}", userId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * 从Redis缓存中删除用户权限
     */
    public void removePermissions(Long userId) {
        try {
            String key = formatKey(userId);
            cacheService.del(key);
            log.debug("Successfully removed permissions from Redis cache for user {}", userId);
        } catch (Exception e) {
            log.error("Failed to remove permissions from Redis for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to remove permissions from Redis", e);
        }
    }

    private String formatKey(Long userId) {
        return String.format(CACHE_KEY_PATTERN, userId);
    }
} 