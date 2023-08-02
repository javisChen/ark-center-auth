package com.ark.center.auth.application.access;

import com.ark.center.auth.client.access.request.ApiAccessRequest;
import com.ark.center.auth.client.access.response.ApiAccessResponse;
import com.ark.center.auth.client.access.response.UserResponse;
import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationToken;
import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.center.auth.infra.config.SecurityCoreProperties;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
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

    private final SecurityCoreProperties securityCoreProperties;
    public ApiAccessResponse getApiAccess(ApiAccessRequest request) {

        SecurityContext context = SecurityContextHolder.getContext();

        String requestUri = request.getRequestUri();
        String applicationCode = "0";
        String method = request.getHttpMethod();
        // 先尝试uri是否匹配系统中存在的包含路径参数的api，如果存在的话就替换成统一的格式
        requestUri = attemptReplaceHasPathVariableUrl(requestUri);

        // 尝试是否匹配白名单中的uri
        if (isMatchDefaultAllowUrl(requestUri)) {
            return ApiAccessResponse.success();
        }

        // 检查API是否只需认证
        if (isMatchJustNeedAuthenticationUri(requestUri, method)) {
            return ApiAccessResponse.success();
        }

        Authentication authentication = context.getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return ApiAccessResponse.success(false);
        }

        // 检查API是否需要授权
        if (isMatchNoNeedAuthorizationUri(requestUri, method)) {
            return ApiAccessResponse.success();
        }

        // 检查是否有API访问权
        boolean access = access(requestUri, applicationCode, method, ((LoginAuthenticationToken) authentication).getLoginUser().getUserCode());
        if (access) {
            return ApiAccessResponse.success(convertToUserResponse(((LoginAuthenticationToken) authentication).getLoginUser()));
        }
        return ApiAccessResponse.success(false);
    }



    private boolean access(String requestUri, String applicationCode, String method, String userCode) {
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

    public boolean isMatchDefaultAllowUrl(String requestUri) {
        List<String> allowList = securityCoreProperties.getAllowList();
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
     * 系统的无需授权资源 + 配置上的定义
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchNoNeedAuthorizationUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNoNeedAuthorizationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证的资源
     * 系统的无需授权资源 + 配置上的定义
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchJustNeedAuthenticationUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNoNeedAuthenticationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    private boolean isMatchUri(Map<String, String> cache, String requestUri, String method) {
        if (MapUtils.isEmpty(cache)) {
            return false;
        }
        return cache.get(ApiCommonUtils.createKey(requestUri, method)) != null;
    }

}
