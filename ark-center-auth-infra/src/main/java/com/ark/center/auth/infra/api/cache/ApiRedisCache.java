package com.ark.center.auth.infra.api.cache;

import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.ApiCacheKey;
import com.ark.component.cache.CacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * API Redis缓存管理
 * 使用Hash结构存储API数据，支持单个API的更新和获取
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApiRedisCache {

    private static final String APP_PREFIX = "auth";
    private static final String CACHE_KEY = "apis";
    private static final Long CACHE_TTL_DAYS = 7L;

    private final CacheService cacheService;

    /**
     * 保存API数据到Redis缓存
     * 使用Hash结构存储，key为API的uri:method，value为API的JSON字符串
     */
    public void saveApiCache(List<ApiMeta> apis) {
        try {
            Map<String, Object> apiMap = apis.stream()
                    .collect(Collectors.toMap(
                            ApiCacheKey::generateRedisKey,
                            JSON::toJSONString
                    ));
            
            cacheService.hMSet(CACHE_KEY, apiMap, CACHE_TTL_DAYS, TimeUnit.DAYS);
            log.info("Successfully saved {} APIs to Redis cache", apis.size());
        } catch (Exception e) {
            log.error("Failed to save API cache to Redis: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to save API cache to Redis", e);
        }
    }

    /**
     * 从Redis缓存加载API数据
     */
    public Optional<List<ApiMeta>> loadApiCache() {
        try {
            Map<Object, Object> entries = cacheService.hGetAll(CACHE_KEY);
            if (entries == null || entries.isEmpty()) {
                log.info("No API cache found in Redis");
                return Optional.empty();
            }

            List<ApiMeta> apis = entries.values().stream()
                    .map(value -> JSON.parseObject((String) value, ApiMeta.class))
                    .collect(Collectors.toList());
            
            log.info("Successfully loaded {} APIs from Redis cache", apis.size());
            return Optional.of(apis);
        } catch (Exception e) {
            log.error("Failed to load API cache from Redis: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * 更新单个API的缓存
     */
    public void updateApiCache(ApiMeta api) {
        try {
            String key = ApiCacheKey.generateRedisKey(api);
            cacheService.hMSet(CACHE_KEY,
                Map.of(key, JSON.toJSONString(api)), 
                CACHE_TTL_DAYS, TimeUnit.DAYS);
            log.info("Successfully updated API cache for {}", key);
        } catch (Exception e) {
            log.error("Failed to update API cache: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to update API cache", e);
        }
    }

    /**
     * 获取单个API的缓存
     */
    public Optional<ApiMeta> getApiCache(String uri, String method) {
        try {
            String key = ApiCacheKey.generateRedisKey(uri, method);
            Object value = cacheService.hGet(CACHE_KEY, key);
            if (value == null) {
                return Optional.empty();
            }
            return Optional.of(JSON.parseObject((String) value, ApiMeta.class));
        } catch (Exception e) {
            log.error("Failed to get API cache: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * 从Redis缓存中删除单个API
     */
    public void removeApiCache(ApiMeta api) {
        try {
            String key = ApiCacheKey.generateRedisKey(api);
            cacheService.hDel(CACHE_KEY, key);
            log.info("Successfully removed API cache for {}", key);
        } catch (Exception e) {
            log.error("Failed to remove API cache: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to remove API cache", e);
        }
    }

    /**
     * 删除Redis中的API缓存
     */
    public void deleteApiCache() {
        try {
            cacheService.del(CACHE_KEY);
            log.info("Successfully deleted API cache from Redis");
        } catch (Exception e) {
            log.error("Failed to delete API cache from Redis: {}", e.getMessage(), e);
        }
    }
} 