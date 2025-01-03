package com.ark.center.auth.infra.authentication.api;

import com.ark.center.auth.infra.AuthMessageSource;
import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.service.UserPermissionService;
import com.ark.center.auth.infra.api.service.ApiAccessControlService;
import com.ark.component.security.base.user.AuthUser;
import com.ark.component.security.core.authentication.AuthenticatedToken;
import com.ark.component.security.core.exception.AuthException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StopWatch;

import java.util.List;

@Slf4j
public final class ApiAccessAuthenticationProvider implements AuthenticationProvider {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ApiAccessControlService apiAccessControlService;
    private final UserPermissionService userPermissionService;
    private final MessageSourceAccessor messages = AuthMessageSource.getAccessor();

    public ApiAccessAuthenticationProvider(ApiAccessControlService apiAccessControlService,
                                           UserPermissionService userPermissionService) {
        this.apiAccessControlService = apiAccessControlService;
        this.userPermissionService = userPermissionService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        StopWatch stopWatch = new StopWatch();
        stopWatch.start("API Access Control");
        
        try {
            ApiAccessAuthenticateRequest request = (ApiAccessAuthenticateRequest) authentication.getPrincipal();
            String requestUri = request.getRequestUri();
            String method = request.getHttpMethod();

            if (log.isDebugEnabled()) {
                log.debug("Starting API access check - URI: {}, Method: {}", requestUri, method);
            }

            // 替换路径参数
            requestUri = apiAccessControlService.matchDynamicPath(requestUri);

            ApiAccessAuthenticationToken authenticated = ApiAccessAuthenticationToken.authenticated(request, request.getAccessToken());

            // 检查是否无需认证和授权
            if (apiAccessControlService.allowsAnonymousAccess(requestUri, method)) {
                log.debug("API access permitted - no auth required for URI: {}", requestUri);
                return authenticated;
            }

            // 获取当前认证信息
            AuthenticatedToken loginAuthentication = ((AuthenticatedToken) SecurityContextHolder.getContext().getAuthentication());
            boolean isAuthenticated = loginAuthentication != null && loginAuthentication.isAuthenticated();

            // 验证认证状态
            if (!isAuthenticated) {
                log.warn("API access denied - user not authenticated for URI: {}", requestUri);
                throw AuthException.of(
                        HttpStatus.UNAUTHORIZED.value(),
                        messages.getMessage("ApiAccessAuthenticationProvider.authenticationRequired",
                                "Authentication is required")
                );
            }

            AuthUser loginUser = loginAuthentication.getAuthUser();

            // 超级管理员直接放行
            if (loginUser.getIsSuperAdmin()) {
                if (log.isDebugEnabled()) {
                    log.debug("API access permitted - SuperAdmin access for URI: {}", requestUri);
                }
                return authenticated;
            }

            // 检查是否只需认证
            if (apiAccessControlService.requiresAuthenticationOnly(requestUri, method)) {
                if (log.isDebugEnabled()) {
                    log.debug("API access permitted - authentication only for URI: {}", requestUri);
                }
                return authenticated;
            }

            // 检查授权
            if (apiAccessControlService.requiresAuthorization(requestUri, method)) {
                if (hasPermission(requestUri, method, loginUser)) {
                    if (log.isDebugEnabled()) {
                        log.debug("API access permitted - authorized access for user: {}, URI: {}",
                                loginUser.getUsername(), requestUri);
                    }
                    return authenticated;
                }
            }

            log.warn("API access denied - insufficient permissions for user: {}, URI: {}", 
                    loginUser.getUsername(), requestUri);
            throw AuthException.of(
                HttpStatus.FORBIDDEN.value(), 
                messages.getMessage("ApiAccessAuthenticationProvider.insufficientPermissions", 
                    "Insufficient permissions")
            );
        } finally {
            stopWatch.stop();
            if (log.isDebugEnabled()) {
                log.debug("API access control completed in {}ms", stopWatch.getTotalTimeMillis());
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiAccessAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private boolean hasPermission(String requestUri, String method, AuthUser user) {
        List<AuthUserApiPermission> apiPermissions = userPermissionService.queryUserApiPermission(user.getUserId());
        return apiPermissions.stream()
                .anyMatch(item -> pathMatcher.match(item.getUri(), requestUri)
                        && item.getMethod().equals(method));
    }
}
