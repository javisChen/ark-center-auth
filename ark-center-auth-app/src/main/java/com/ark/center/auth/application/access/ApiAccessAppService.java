package com.ark.center.auth.application.access;

import cn.hutool.core.collection.CollUtil;
import com.ark.center.auth.client.access.dto.ApiAccessAuthenticateDTO;
import com.ark.center.auth.infra.support.AuthMessageSource;
import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
import com.ark.center.auth.infra.user.service.UserPermissionService;
import com.ark.component.security.base.authentication.AuthUser;
import com.ark.component.security.core.authentication.AuthenticatedToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StopWatch;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class ApiAccessAppService {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final UserPermissionService userPermissionService;
    private final MessageSourceAccessor messages = AuthMessageSource.getAccessor();
    private final ApiResourceRepository apiResourceRepository;

    public ApiAccessAuthenticateDTO authenticate(ApiAccessAuthenticateQuery request) throws AuthenticationException {
        StopWatch stopWatch = new StopWatch("API Access Control");
        String requestUri = request.getRequestUri();
        String method = request.getHttpMethod();

        try {
            if (log.isDebugEnabled()) {
                log.debug("Starting API access check - URI: {}, Method: {}", requestUri, method);
            }

            // 获取API信息并进行访问控制
            stopWatch.start("Access Control");
            ApiMeta apiMeta = matchApi(requestUri, method);
            ApiAccessAuthenticateDTO allowed = ApiAccessAuthenticateDTO.allowed();
            if (apiMeta == null) {
                log.warn("API endpoint not registered in IAM system: {} {}", method, requestUri);
                return allowed;
            }

            // 根据API类型进行访问控制
            if (apiMeta.allowsAnonymousAccess()) {
                if (log.isDebugEnabled()) {
                    log.debug("API access permitted - anonymous access for URI: {}", requestUri);
                }
                return allowed;
            }

            // 验证认证状态
            AuthenticatedToken authenticatedToken = (AuthenticatedToken) SecurityContextHolder.getContext().getAuthentication();
            if (!isAuthenticated(authenticatedToken)) {
                log.warn("Authentication failed - token is null or expired: {}", authenticatedToken);
                return ApiAccessAuthenticateDTO.denied(messages.getMessage("ApiAccessAuthenticationProvider.authenticationRequired",
                        "Authentication is required"));
            }

            AuthUser authUser = authenticatedToken.getAuthUser();

            // 超级管理员直接放行
            if (authUser.getIsSuperAdmin()) {
                if (log.isDebugEnabled()) {
                    log.debug("API access permitted - SuperAdmin access for URI: {}", requestUri);
                }
                return allowed;
            }

            // 根据API类型检查权限
            if (apiMeta.authenticationRequired()) {
                if (log.isDebugEnabled()) {
                    log.debug("API access permitted - authentication only for URI: {}", requestUri);
                }
                return allowed;
            }

            stopWatch.stop();

            // 授权检查
            stopWatch.start("Permission Check");
            if (apiMeta.authorizationRequired()) {
                if (checkUserApiPermission(apiMeta, authUser)) {
                    if (log.isDebugEnabled()) {
                        log.debug("API access permitted - authorized access for user: {}, URI: {}",
                                authUser.getUsername(), requestUri);
                    }
                    return allowed;
                }
                log.warn("API access denied - insufficient permissions for user: {}, URI: {}",
                        authUser.getUsername(), requestUri);
                return ApiAccessAuthenticateDTO.denied(messages.getMessage("ApiAccessAuthenticationProvider.insufficientPermissions",
                        "Insufficient permissions"));
            }

            return ApiAccessAuthenticateDTO.denied(messages.getMessage("Unknown API type"));
        } finally {
            stopWatch.stop();
            if (log.isDebugEnabled()) {
                log.debug("API access control timing details:\n{}", stopWatch.prettyPrint(TimeUnit.MILLISECONDS));
            }
        }
    }

    /**
     * 获取API信息
     * 1. 先尝试精确匹配
     * 2. 如果精确匹配失败，尝试模式匹配
     */
    public ApiMeta matchApi(String requestUri, String method) {
        // 1. 先尝试精确匹配
        ApiMeta exactMatch = apiResourceRepository.getExactApi(requestUri, method);
        if (exactMatch != null) {
            return exactMatch;
        }

        // todo 如果动态API数量有一定规模的话这里匹配会有性能问题
        //  当然我们可以尽可能地采用空间换时间的方案不断地优化，但目前来说投入太多时间来优化没有任何价值
        //  我们在定义API的时候用规范来约束尽量避免路径参数的API即可完美规避
        List<ApiMeta> dynamicApis = apiResourceRepository.getDynamicApis()
                .stream()
                .filter(api -> pathMatcher.match(api.getUri(), requestUri) && api.getMethod().equalsIgnoreCase(method))
                .toList();
        if (CollUtil.isNotEmpty(dynamicApis)) {
            return dynamicApis.getFirst();
        }
        return null;
    }

    private boolean isAuthenticated(AuthenticatedToken authentication) {
        return authentication != null && authentication.isAuthenticated();
    }

    private boolean checkUserApiPermission(ApiMeta apiMeta, AuthUser user) {
        return userPermissionService.checkUserApiPermission(user.getUserId(), apiMeta.getId());
    }
}
