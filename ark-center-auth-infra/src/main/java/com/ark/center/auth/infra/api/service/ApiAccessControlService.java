package com.ark.center.auth.infra.api.service;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ApiAccessControlService {
    
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ApiResourceRepository apiResourceRepository;

    /**
     * 获取API信息
     */
    public Optional<ApiMeta> getApi(String requestUri, String method) {
        // 先尝试替换动态路径
        String normalizedUri = matchDynamicPath(requestUri);
        return apiResourceRepository.getApi(normalizedUri, method);
    }

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
        return apiResourceRepository.isAuthorizationRequired(requestUri, method);
    }

    /**
     * 检查API是否允许匿名访问
     * 无需认证也无需授权
     */
    public boolean allowsAnonymousAccess(String requestUri, String method) {
        return apiResourceRepository.isAnonymousAccess(requestUri, method);
    }

    /**
     * 检查API是否只需要认证
     * 只需登录验证，无需额外的权限校验
     */
    public boolean requiresAuthenticationOnly(String requestUri, String method) {
        return apiResourceRepository.requiresAuthenticationOnly(requestUri, method);
    }
} 