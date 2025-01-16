//package com.ark.center.auth.infra.authentication.api;
//
//import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
//import com.ark.center.auth.infra.AuthMessageSource;
//import com.ark.center.auth.infra.api.ApiMeta;
//import com.ark.center.auth.infra.user.AuthUserApiPermission;
//import com.ark.center.auth.infra.user.service.UserPermissionService;
//import com.ark.center.auth.infra.api.service.ApiAccessControlService;
//import com.ark.component.security.base.user.AuthUser;
//import com.ark.component.security.core.authentication.AuthenticatedToken;
//import com.ark.component.security.core.exception.AuthException;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.context.support.MessageSourceAccessor;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.util.AntPathMatcher;
//import org.springframework.util.StopWatch;
//
//import java.util.List;
//import java.util.Optional;
//import java.util.concurrent.TimeUnit;
//
//@Slf4j
//public final class ApiAccessAuthenticationProvider implements AuthenticationProvider {
//
//    private final AntPathMatcher pathMatcher = new AntPathMatcher();
//    private final ApiAccessControlService apiAccessControlService;
//    private final UserPermissionService userPermissionService;
//    private final MessageSourceAccessor messages = AuthMessageSource.getAccessor();
//
//    public ApiAccessAuthenticationProvider(ApiAccessControlService apiAccessControlService,
//                                           UserPermissionService userPermissionService) {
//        this.apiAccessControlService = apiAccessControlService;
//        this.userPermissionService = userPermissionService;
//    }
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        StopWatch stopWatch = new StopWatch("API Access Control");
//        ApiAccessAuthenticateQuery request = (ApiAccessAuthenticateQuery) authentication.getPrincipal();
//        String requestUri = request.getRequestUri();
//        String method = request.getHttpMethod();
//
//        try {
//            if (log.isDebugEnabled()) {
//                log.debug("Starting API access check - URI: {}, Method: {}", requestUri, method);
//            }
//
//            // 替换路径参数
//            stopWatch.start("Dynamic Path Match");
//            requestUri = apiAccessControlService.matchDynamicPath(requestUri);
//            stopWatch.stop();
//
//            ApiAccessAuthenticationToken authenticated = ApiAccessAuthenticationToken.authenticated(request, request.getAccessToken());
//
//            // 获取API信息并进行访问控制
//            stopWatch.start("Access Control");
//            Optional<ApiMeta> apiOpt = apiAccessControlService.getApi(requestUri, method);
//            if (apiOpt.isEmpty()) {
//                log.warn("API endpoint not registered in IAM system: {} {}", method, requestUri);
//                throw AuthException.of(
//                    HttpStatus.FORBIDDEN.value(),
//                    messages.getMessage(
//                        "ApiAccessAuthenticationProvider.apiNotRegistered",
//                        "API endpoint not registered in access control system"
//                    )
//                );
//            }
//
//            ApiMeta api = apiOpt.get();
//
//            // 根据API类型进行访问控制
//            if (api.allowsAnonymousAccess()) {
//                log.debug("API access permitted - anonymous access for URI: {}", requestUri);
//                return authenticated;
//            }
//
//            // 验证认证状态
//            AuthenticatedToken authenticatedToken = (AuthenticatedToken) SecurityContextHolder.getContext().getAuthentication();
//            if (!isAuthenticated(authenticatedToken)) {
//                throw AuthException.of(
//                        HttpStatus.UNAUTHORIZED.value(),
//                        messages.getMessage("ApiAccessAuthenticationProvider.authenticationRequired",
//                                "Authentication is required")
//                );
//            }
//
//            AuthUser authUser = authenticatedToken.getAuthUser();
//
//            // 超级管理员直接放行
//            if (authUser.getIsSuperAdmin()) {
//                if (log.isDebugEnabled()) {
//                    log.debug("API access permitted - SuperAdmin access for URI: {}", requestUri);
//                }
//                return authenticated;
//            }
//
//            // 根据API类型检查权限
//            if (api.authenticationRequired()) {
//                if (log.isDebugEnabled()) {
//                    log.debug("API access permitted - authentication only for URI: {}", requestUri);
//                }
//                return authenticated;
//            }
//
//            stopWatch.stop();
//
//            // 授权检查
//            stopWatch.start("Permission Check");
//            if (api.authorizationRequired()) {
//                if (hasPermission(requestUri, method, authUser)) {
//                    log.debug("API access permitted - authorized access for user: {}, URI: {}",
//                            authUser.getUsername(), requestUri);
//                    return authenticated;
//                }
//                log.warn("API access denied - insufficient permissions for user: {}, URI: {}",
//                        authUser.getUsername(), requestUri);
//                throw AuthException.of(
//                    HttpStatus.FORBIDDEN.value(),
//                    messages.getMessage("ApiAccessAuthenticationProvider.insufficientPermissions",
//                        "Insufficient permissions")
//                );
//            }
//
//            // 未知的API类型
//            log.warn("Unknown API type for URI: {}", requestUri);
//            throw AuthException.of(HttpStatus.FORBIDDEN.value(), "Unknown API type");
//        } finally {
//            stopWatch.stop();
//            if (log.isDebugEnabled()) {
//                log.debug("API access control timing details:\n{}", stopWatch.prettyPrint(TimeUnit.MILLISECONDS));
//            }
//        }
//    }
//
//    private boolean isAuthenticated(AuthenticatedToken authentication) {
//        return authentication != null && authentication.isAuthenticated();
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return ApiAccessAuthenticationToken.class.isAssignableFrom(authentication);
//    }
//
//    private boolean hasPermission(String requestUri, String method, AuthUser user) {
//        List<AuthUserApiPermission> apiPermissions = userPermissionService.queryUserApiPermission(user.getUserId());
//        return apiPermissions.stream()
//                .anyMatch(item -> pathMatcher.match(item.getUri(), requestUri)
//                        && item.getMethod().equals(method));
//    }
//}
