package com.ark.center.auth.infra.api.repository;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.ApiCacheKey;
import com.ark.center.auth.infra.api.cache.ApiRedisCache;
import com.ark.center.auth.infra.user.gateway.ApiGateway;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * API资源缓存
 * 用于存储和管理API的访问控制信息
 */
@Component
@Slf4j
public class ApiResourceRepository implements InitializingBean {

    private final ApiGateway apiGateway;
    private final ApiRedisCache apiRedisCache;

    /**
     * API缓存
     * key: ApiKey(uri, method)
     * value: ApiMeta
     */
    @Getter
    private Map<ApiCacheKey, ApiMeta> apiCache;

    /**
     * 动态路径API缓存
     * 包含路径参数的API列表
     * 例如：["/api/v1/users/{id}", "/api/v1/orders/{orderId}/items/{itemId}"]
     */
    @Getter
    private List<String> dynamicPathApiCache;

    public ApiResourceRepository(ApiGateway apiGateway, ApiRedisCache apiRedisCache) {
        this.apiGateway = apiGateway;
        this.apiRedisCache = apiRedisCache;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        refresh(true);
    }

    public synchronized void refresh(boolean throwEx) {
        try {
            // 尝试从Redis缓存加载
            List<ApiMeta> apis = apiRedisCache.loadApiCache()
                    .orElseGet(() -> {
                        // 如果Redis缓存不存在，从IAM服务获取并保存到缓存
                        List<ApiMeta> remoteApis = apiGateway.retrieveApis();
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
     * 强制从IAM服务刷新API数据
     */
    public synchronized void forceRefresh() {
        try {
            // 从IAM服务获取最新数据
            List<ApiMeta> apis = apiGateway.retrieveApis();
            
            // 更新Redis缓存
            apiRedisCache.saveApiCache(apis);
            
            // 更新内存缓存
            updateLocalCache(apis);
            log.info("Successfully force refreshed API cache with {} APIs", apis.size());
        } catch (Exception e) {
            log.error("Failed to force refresh API cache: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * 更新本地内存缓存
     */
    private void updateLocalCache(List<ApiMeta> apis) {
        apiCache = apis.stream().collect(Collectors.toMap(
            api -> new ApiCacheKey(api.getUri(), api.getMethod()),
            api -> api
        ));
        
        dynamicPathApiCache = apis.stream()
                .filter(item -> item.getHasPathVariable().equals(true))
                .map(ApiMeta::getUri)
                .collect(Collectors.toList());
    }

    /**
     * 获取API信息
     */
    public Optional<ApiMeta> getApi(String uri, String method) {
        ApiMeta api = apiCache.get(new ApiCacheKey(uri, method));
        return Optional.ofNullable(api);
    }

    /**
     * 检查API是否允许匿名访问
     */
    public boolean isAnonymousAccess(String uri, String method) {
        return getApi(uri, method)
                .map(ApiMeta::allowsAnonymousAccess)
                .orElse(false);
    }

    /**
     * 检查API是否需要授权
     */
    public boolean isAuthorizationRequired(String uri, String method) {
        return getApi(uri, method)
                .map(ApiMeta::authorizationRequired)
                .orElse(false);
    }

    /**
     * 检查API是否只需要认证
     * 只需登录验证，无需额外的权限校验
     */
    public boolean requiresAuthenticationOnly(String uri, String method) {
        return getApi(uri, method)
                .map(ApiMeta::authenticationRequired)
                .orElse(false);
    }
}
