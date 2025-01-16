package com.ark.center.auth.infra.api.repository;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.ApiCacheKey;
import com.ark.center.auth.infra.api.cache.ApiRedisCache;
import com.ark.center.auth.infra.user.gateway.ApiGateway;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * API资源缓存
 * 使用线程安全的集合类来存储API数据
 */
@Component
@Slf4j
public class ApiResourceRepository implements InitializingBean {

    private final ApiGateway apiGateway;
    private final ApiRedisCache apiRedisCache;

    /**
     * 精确路径API缓存
     * key: ApiCacheKey(uri, method)
     */
    private Map<ApiCacheKey, ApiMeta> exactPathCache = new ConcurrentHashMap<>();

    /**
     * 动态路径API缓存
     */
    private List<ApiMeta> dynamicPathCache = new CopyOnWriteArrayList<>();

    public ApiResourceRepository(ApiGateway apiGateway, ApiRedisCache apiRedisCache) {
        this.apiGateway = apiGateway;
        this.apiRedisCache = apiRedisCache;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        refresh(true);
    }

    public void refresh(boolean throwEx) {
        try {
            // 尝试从Redis缓存加载
            List<ApiMeta> apis = apiRedisCache.loadApiCache()
                    .orElseGet(() -> {
                        // 如果Redis缓存不存在，从IAM服务获取并保存到缓存
                        List<ApiMeta> remoteApis = apiGateway.queryApis();
                        apiRedisCache.saveApiCache(remoteApis);
                        return remoteApis;
                    });

            // 更新内存缓存
            updateLocalCache(apis);
            log.info("Successfully refreshed API cache with {} APIs", apis.size());
        } catch (Exception e) {
            log.error("Failed to refresh API cache: {}", e.getMessage(), e);
            if (throwEx) {
                throw e;
            }
        }
    }

    /**
     * 添加API到指定的缓存集合中
     */
    private void addToCache(ApiMeta api, Map<ApiCacheKey, ApiMeta> exactCache, List<ApiMeta> dynamicCache) {
        if (api.getIsDynamicPath()) {
            dynamicCache.add(api);
        } else {
            exactCache.put(new ApiCacheKey(api.getUri(), api.getMethod()), api);
        }
    }

    /**
     * 添加API到本地缓存中
     */
    private void addToLocalCache(ApiMeta api) {
        addToCache(api, exactPathCache, dynamicPathCache);
    }

    /**
     * 更新本地内存缓存
     */
    private void updateLocalCache(List<ApiMeta> apis) {
        // 创建新的缓存实例
        Map<ApiCacheKey, ApiMeta> newExactPathCache = new ConcurrentHashMap<>();
        List<ApiMeta> newDynamicPathCache = new CopyOnWriteArrayList<>();

        // 分类存储API
        for (ApiMeta api : apis) {
            addToCache(api, newExactPathCache, newDynamicPathCache);
        }

        // 原子性地替换缓存引用
        this.exactPathCache = newExactPathCache;
        this.dynamicPathCache = newDynamicPathCache;
    }

    /**
     * 从本地缓存中移除指定的API
     */
    private void removeFromLocalCache(String uri, String method) {
        ApiCacheKey key = new ApiCacheKey(uri, method);
        exactPathCache.remove(key);
        dynamicPathCache.removeIf(item -> 
            item.getUri().equals(uri) && item.getMethod().equals(method)
        );
    }

    /**
     * 更新单个API缓存
     * @throws RuntimeException 如果Redis缓存更新失败
     */
    public void updateApi(ApiMeta api) {
        // 1. 先更新Redis缓存，如果失败则抛出异常，本地缓存保持不变
        try {
            apiRedisCache.updateApiCache(api);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update Redis cache, local cache remains unchanged", e);
        }
        
        // 2. Redis更新成功后，再更新本地缓存
        removeFromLocalCache(api.getUri(), api.getMethod());
        addToLocalCache(api);

        log.info("Successfully updated API cache for {}", api.getUri() + ":" + api.getMethod());
    }

    /**
     * 删除API缓存
     * @throws RuntimeException 如果Redis缓存删除失败
     */
    public void removeApi(ApiMeta api) {
        // 1. 先从Redis缓存中移除，如果失败则抛出异常，本地缓存保持不变
        try {
            apiRedisCache.removeApiCache(api);
        } catch (Exception e) {
            throw new RuntimeException("Failed to remove from Redis cache, local cache remains unchanged", e);
        }

        // 2. Redis删除成功后，再从本地缓存中移除
        removeFromLocalCache(api.getUri(), api.getMethod());
        log.info("Successfully removed API cache for {}", api.getUri() + ":" + api.getMethod());
    }

    /**
     * 获取精确匹配的API
     */
    public ApiMeta getExactApi(String uri, String method) {
        return exactPathCache.get(new ApiCacheKey(uri, method));
    }

    /**
     * 获取指定HTTP方法的所有动态路径API
     */
    public List<ApiMeta> getDynamicApis() {
        return dynamicPathCache;
    }
}
