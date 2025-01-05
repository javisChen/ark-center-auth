package com.ark.center.auth.infra.api.service;

import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import com.ark.center.auth.infra.api.domain.ApiKey;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.MapUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ApiAccessControlService {
    
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final ApiResourceRepository apiResourceRepository;

    /**
     * 将包含路径变量的请求URL匹配到对应的API模板
     * 例如: /users/123/profile -> /users/{id}/profile
     */
    public String matchDynamicPath(String requestUri) {
        List<String> hasPathVariableApiCache = apiResourceRepository.getDynamicPathApiCache();
        return hasPathVariableApiCache.stream()
                .filter(item -> pathMatcher.match(item, requestUri))
                .findFirst()
                .orElse(requestUri);
    }

    /**
     * 检查API是否需要进行权限校验
     * 需要同时满足认证和授权要求
     */
    public boolean requiresAuthorization(String requestUri, String method) {
        Map<ApiKey, String> cache = apiResourceRepository.getAuthorizationRequiredApiCache();
        return matchUri(cache, requestUri, method);
    }

    /**
     * 检查API是否允许匿名访问
     * 无需认证也无需授权
     */
    public boolean allowsAnonymousAccess(String requestUri, String method) {
        Map<ApiKey, String> cache = apiResourceRepository.getAnonymousAccessApiCache();
        return matchUri(cache, requestUri, method);
    }

    /**
     * 检查API是否仅需要认证
     * 只需要登录，无需额外的权限校验
     */
    public boolean requiresAuthenticationOnly(String requestUri, String method) {
        Map<ApiKey, String> cache = apiResourceRepository.getAuthenticationRequiredApiCache();
        return matchUri(cache, requestUri, method);
    }

    private boolean matchUri(Map<ApiKey, String> cache, String requestUri, String method) {
        if (MapUtils.isEmpty(cache)) {
            return false;
        }
        return cache.get(new ApiKey(requestUri, method)) != null;
    }
} 