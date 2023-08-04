package com.ark.center.auth.application.access;

import com.ark.center.auth.application.access.support.ApiCacheHolder;
import com.ark.center.auth.client.access.request.ApiAccessRequest;
import com.ark.center.auth.client.access.response.ApiAccessResponse;
import com.ark.center.auth.client.access.response.UserResponse;
import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.api.support.ApiCommonUtils;
import com.ark.center.auth.infra.config.AuthProperties;
import com.ark.component.security.base.user.LoginUser;
import com.ark.component.security.core.authentication.LoginAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AccessAppService {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final ApiCacheHolder apiCacheHolder;

    private final UserPermissionService userPermissionService;

    private final AuthProperties authProperties;
    public ApiAccessResponse getApiAccess(ApiAccessRequest request) {

        SecurityContext context = SecurityContextHolder.getContext();

        String requestUri = request.getRequestUri();
        String applicationCode = "0";
        String method = request.getHttpMethod();
        // 先尝试uri是否匹配系统中存在的包含路径参数的api，如果存在的话就替换成统一的格式
        requestUri = attemptReplaceHasPathVariableUrl(requestUri);

//        // 尝试是否匹配黑名单中的URI
//        if (isMatchBlockUri(requestUri)) {
//            return ApiAccessResponse.fail(HttpStatus.FORBIDDEN.value());
//        }
//
//        // 尝试是否匹配白名单中的URI
//        if (isMatchAllowUri(requestUri)) {
//            return ApiAccessResponse.success();
//        }

        // 检查API是否无需认证和授权
        if (isMatchNoNeedAuthUri(requestUri, method)) {
            return ApiAccessResponse.success();
        }

        Authentication authentication = context.getAuthentication();
        boolean isAuthenticated = authentication != null && authentication.isAuthenticated();

        // 检查API是否只需认证并且当前用户是否认证成功
        if (isMatchJustNeedAuthenticationUri(requestUri, method)) {
            if (isAuthenticated) {
                return ApiAccessResponse.success();
            } else {
                return ApiAccessResponse.fail(HttpStatus.UNAUTHORIZED.value());
            }
        }

        // 如果还未认证，直接返回
        if (!isAuthenticated) {
            return ApiAccessResponse.fail(HttpStatus.UNAUTHORIZED.value());
        }

        // 检查API是否需要授权
        if (isMatchNeedAuthorizationUri(requestUri, method)) {
            // 检查是否有API访问权
            String userCode = ((LoginAuthenticationToken) authentication).getLoginUser().getUserCode();
            boolean hasPermission = hasPermission(requestUri, applicationCode, method, userCode);
            if (hasPermission) {
                return ApiAccessResponse.success();
            }
        }
        //
        return ApiAccessResponse.fail(HttpStatus.FORBIDDEN.value());
    }

    private boolean hasPermission(String requestUri, String applicationCode, String method, String userCode) {
        return userPermissionService.checkHasApiPermission(applicationCode, userCode, requestUri, method);
    }

    private UserResponse convertToUserResponse(LoginUser userContext) {
        UserResponse userResponse = new UserResponse();
        userResponse.setUserId(userContext.getUserId());
        userResponse.setUserCode(userContext.getUserCode());
        userResponse.setUsername(userContext.getUsername());
        userResponse.setIsSuperAdmin(userContext.getIsSuperAdmin());
        return userResponse;
    }

    public boolean isMatchBlockUri(String requestUri) {
        List<String> allowList = authProperties.getBlockList();
        if (CollectionUtils.isEmpty(allowList)) {
            return false;
        }
        return allowList.stream()
                .anyMatch(item -> pathMatcher.match(item, requestUri));
    }

    public boolean isMatchAllowUri(String requestUri) {
        List<String> allowList = authProperties.getAllowList();
        if (CollectionUtils.isEmpty(allowList)) {
            return false;
        }
        return allowList.stream()
                .anyMatch(item -> pathMatcher.match(item, requestUri));
    }

    public String attemptReplaceHasPathVariableUrl(String requestUri) {
        List<String> hasPathVariableApiCache = apiCacheHolder.getHasPathVariableApiCache();
        return hasPathVariableApiCache.stream()
                .filter(item -> pathMatcher.match(item, requestUri))
                .findFirst()
                .orElse(requestUri);
    }

    /**
     * 尝试匹配无需授权的资源
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchNeedAuthorizationUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNeedAuthorizationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证授权的资源
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchNoNeedAuthUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNoNeedAuthApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证的资源
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchJustNeedAuthenticationUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNeedAuthenticationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    private boolean isMatchUri(Map<String, String> cache, String requestUri, String method) {
        if (MapUtils.isEmpty(cache)) {
            return false;
        }
        return cache.get(ApiCommonUtils.createKey(requestUri, method)) != null;
    }

}
