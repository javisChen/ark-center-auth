//package com.ark.center.auth.infra.authentication;
//
//import com.ark.center.auth.infra.config.SecurityCoreProperties;
//import com.ark.center.iam.client.access.response.UserResponse;
//import com.ark.center.iam.client.permission.response.LoginUserResponse;
//import com.ark.component.common.ParamsChecker;
//import jakarta.servlet.http.HttpServletRequest;
//import org.apache.commons.collections4.CollectionUtils;
//import org.apache.commons.collections4.MapUtils;
//import org.springframework.security.access.AccessDeniedException;
//import org.springframework.security.authorization.AuthorizationDecision;
//import org.springframework.security.authorization.AuthorizationManager;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContext;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
//import org.springframework.util.AntPathMatcher;
//
//import java.util.List;
//import java.util.Map;
//import java.util.function.Supplier;
//
//public class ApiAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
//
//    private final AntPathMatcher pathMatcher = new AntPathMatcher();
//
//    private final ApiCacheHolder apiCacheHolder;
//
//    private final UserPermissionService userPermissionService;
//
//    private final IUserTokenCacheService iUserTokenCacheService;
//
//    private final SecurityCoreProperties securityCoreProperties;
//
//    public ApiAuthorizationManager(SecurityCoreProperties securityCoreProperties) {
//        this.securityCoreProperties = securityCoreProperties;
//    }
//
//    @Override
//    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
//        AuthorizationManager.super.verify(authentication, object);
//    }
//
//    private boolean isGranted(Authentication authentication, RequestAuthorizationContext requestAuthorizationContext) {
//        HttpServletRequest request = requestAuthorizationContext.getRequest();
//        String requestUri = request.getRequestURI();
//        String applicationCode = "0";
//        String method = request.getMethod();
//        // 先尝试uri是否匹配系统中存在的包含路径参数的api，如果存在的话就替换成统一的格式
//        requestUri = attemptReplaceHasPathVariableUrl(requestUri);
//
//        // 尝试是否匹配白名单中的uri
//        if (isMatchDefaultAllowUrl(requestUri)) {
//            return true;
//        }
//
//        // 检查API是否只需认证
//        if (isMatchJustNeedAuthenticationUri(requestUri, method)) {
//            return true;
//        }
//
//        if (authentication == null || !authentication.isAuthenticated()) {
//            return false;
//        }
//        // 检查API是否需要授权
//        if (isMatchNoNeedAuthorizationUri(requestUri, method)) {
//            return true;
//        }
//
//        // 检查是否有API访问权
//        return access(requestUri, applicationCode, method, userContext.getUserCode());
//
//    }
//
//    @Override
//    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
//        boolean granted = isGranted(authentication.get(), requestAuthorizationContext);
//        return new AuthorizationDecision(granted);
//    }
//
//
//    private boolean access(String requestUri, String applicationCode, String method, String userCode) {
//        return userPermissionService.checkHasApiPermission(applicationCode, userCode, requestUri, method);
//    }
//
//    private UserResponse convertToUserResponse(LoginUserResponse userContext) {
//        UserResponse userResponse = new UserResponse();
//        userResponse.setUserId(userContext.getUserId());
//        userResponse.setUserCode(userContext.getUserCode());
//        userResponse.setUsername(userContext.getUsername());
//        userResponse.setAccessToken(userContext.getAccessToken());
//        userResponse.setExpires(userContext.getExpires());
//        userResponse.setIsSuperAdmin(userContext.getIsSuperAdmin());
//        return userResponse;
//    }
//
//    public boolean isMatchDefaultAllowUrl(String requestUri) {
//        List<String> allowList = securityCoreProperties.getAllowList();
//        if (CollectionUtils.isEmpty(allowList)) {
//            return false;
//        }
//        return allowList.stream()
//                .anyMatch(item -> pathMatcher.match(item, requestUri));
//    }
//
//    public String attemptReplaceHasPathVariableUrl(String requestUri) {
//        List<String> hasPathVariableApiCache = apiCacheHolder.getHasPathVariableApiCache();
//        return hasPathVariableApiCache.stream()
//                .filter(item -> pathMatcher.match(item, requestUri))
//                .findFirst()
//                .orElse(requestUri);
//    }
//
//    /**
//     * 尝试匹配无需授权的资源
//     * 系统的无需授权资源 + 配置上的定义
//     * @return 匹配成功=true，不成功=false
//     */
//    public boolean isMatchNoNeedAuthorizationUri(String requestUri, String method) {
//        Map<String, String> cache = apiCacheHolder.getNoNeedAuthorizationApiCache();
//        return isMatchUri(cache, requestUri, method);
//    }
//
//    /**
//     * 尝试匹配无需认证的资源
//     * 系统的无需授权资源 + 配置上的定义
//     * @return 匹配成功=true，不成功=false
//     */
//    public boolean isMatchJustNeedAuthenticationUri(String requestUri, String method) {
//        Map<String, String> cache = apiCacheHolder.getNoNeedAuthenticationApiCache();
//        return isMatchUri(cache, requestUri, method);
//    }
//
//    private boolean isMatchUri(Map<String, String> cache, String requestUri, String method) {
//        if (MapUtils.isEmpty(cache)) {
//            return false;
//        }
//        return cache.get(ApiCommonUtils.createKey(requestUri, method)) != null;
//    }
//
//}
