package com.ark.center.auth.infra.api.repository;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.domain.ApiKey;
import com.ark.center.auth.infra.user.gateway.ApiGateway;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;

/**
 * API资源缓存
 * 用于存储和管理API的访问控制信息
 */
@Component
@Slf4j
public class ApiResourceRepository implements InitializingBean {

    private final ApiGateway apiGateway;

    /**
     * 允许匿名访问的API缓存
     * key: ApiKey(uri, method)
     * value: uri
     */
    @Getter
    private Map<ApiKey, String> anonymousAccessApiCache;

    /**
     * 需要授权的API缓存
     * key: ApiKey(uri, method)
     * value: uri
     */
    @Getter
    private Map<ApiKey, String> authorizationRequiredApiCache;

    /**
     * 仅需认证的API缓存
     * key: ApiKey(uri, method)
     * value: uri
     */
    @Getter
    private Map<ApiKey, String> authenticationRequiredApiCache;

    /**
     * 动态路径API缓存
     * 包含路径参数的API列表
     * 例如：["/api/v1/users/{id}", "/api/v1/orders/{orderId}/items/{itemId}"]
     */
    @Getter
    private List<String> dynamicPathApiCache;

    public ApiResourceRepository(ApiGateway apiGateway) {
        this.apiGateway = apiGateway;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        refresh(true);
    }

    public synchronized void refresh(boolean throwEx) {
        try {
            List<ApiMeta> apis = apiGateway.retrieveApis();
            anonymousAccessApiCache = collectAnonymousAccessApis(apis);
            authorizationRequiredApiCache = collectAuthorizationRequiredApis(apis);
            authenticationRequiredApiCache = collectAuthenticationRequiredApis(apis);
            dynamicPathApiCache = collectHasPathVariableApis(apis);
        } catch (Exception e) {
            log.error("Failed to refresh API cache: {}", e.getMessage(), e);
            if (throwEx) {
                throw e;
            }
        }
    }

    /**
     * 收集允许匿名访问的API
     */
    private Map<ApiKey, String> collectAnonymousAccessApis(List<ApiMeta> apis) {
        return apis.stream()
                .filter(ApiMeta::noAuthRequired)
                .collect(collectMatchApi());
    }

    /**
     * 收集需要授权的API
     */
    private Map<ApiKey, String> collectAuthorizationRequiredApis(List<ApiMeta> apis) {
        return apis.stream()
                .filter(ApiMeta::authorizationRequired)
                .collect(collectMatchApi());
    }

    /**
     * 收集仅需认证的API
     */
    private Map<ApiKey, String> collectAuthenticationRequiredApis(List<ApiMeta> apis) {
        return apis.stream()
                .filter(ApiMeta::authenticationRequired)
                .collect(collectMatchApi());
    }

    @NotNull
    private Collector<ApiMeta, ?, Map<ApiKey, String>> collectMatchApi() {
        return Collectors.toMap(
            api -> new ApiKey(api.getUri(), api.getMethod()),
            ApiMeta::getUri
        );
    }

    private List<String> collectHasPathVariableApis(List<ApiMeta> apis) {
        return apis.stream()
                .filter(item -> item.getHasPathVariable().equals(true))
                .map(ApiMeta::getUri)
                .collect(Collectors.toList());
    }
}
