package com.ark.center.auth.application.access;

import com.ark.center.auth.client.access.dto.ApiAccessAuthenticateDTO;
import com.ark.center.auth.infra.AuthMessageSource;
import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.service.ApiAccessControlService;
import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.service.UserPermissionService;
import com.ark.component.security.base.user.AuthUser;
import com.ark.component.security.core.authentication.AuthenticatedToken;
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
public class ApiAccessService {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ApiAccessControlService apiAccessControlService;
    private final UserPermissionService userPermissionService;
    private final MessageSourceAccessor messages = AuthMessageSource.getAccessor();

    public ApiAccessService(ApiAccessControlService apiAccessControlService,
                            UserPermissionService userPermissionService) {
        this.apiAccessControlService = apiAccessControlService;
        this.userPermissionService = userPermissionService;
    }

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
            ApiMeta apiMeta = apiAccessControlService.getApi(requestUri, method);
            ApiAccessAuthenticateDTO allowed = ApiAccessAuthenticateDTO.allowed();
            if (apiMeta == null) {
                log.warn("API endpoint not registered in IAM system: {} {}", method, requestUri);
//                return ApiAccessAuthenticateDTO.denied(messages.getMessage(
//                        "ApiAccessAuthenticationProvider.apiNotRegistered",
//                        "API endpoint not registered in access control system"
//                ));
                return allowed;
            }

            // 根据API类型进行访问控制
            if (apiMeta.allowsAnonymousAccess()) {
                log.debug("API access permitted - anonymous access for URI: {}", requestUri);
                return allowed;
            }

            // 验证认证状态
            AuthenticatedToken authenticatedToken = (AuthenticatedToken) SecurityContextHolder.getContext().getAuthentication();
            log.debug("Checking authentication status - Token: {}", authenticatedToken);
            if (!isAuthenticated(authenticatedToken)) {
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
                if (hasPermission(requestUri, method, authUser)) {
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

    private boolean isAuthenticated(AuthenticatedToken authentication) {
        return authentication != null && authentication.isAuthenticated();
    }

    private boolean hasPermission(String requestUri, String method, AuthUser user) {
        List<AuthUserApiPermission> apiPermissions = userPermissionService.queryUserApiPermission(user.getUserId());
        return apiPermissions.stream()
                .anyMatch(item -> {
                    boolean match = pathMatcher.match(item.getUri(), requestUri);
                    return match && item.getMethod().equals(method);
                });
    }


}
