package com.ark.center.auth.infra.authentication.api;

import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.api.support.ApiCommonUtils;
import com.ark.component.security.core.authentication.LoginAuthenticationToken;
import com.ark.component.security.core.authentication.exception.AuthException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.MapUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Map;

@Slf4j
public final class ApiAccessAuthenticationProvider implements AuthenticationProvider {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final ApiCacheHolder apiCacheHolder;

    private final UserPermissionService userPermissionService;

    public ApiAccessAuthenticationProvider(ApiCacheHolder apiCacheHolder, UserPermissionService userPermissionService) {
        this.apiCacheHolder = apiCacheHolder;
        this.userPermissionService = userPermissionService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        ApiAccessAuthenticateRequest request = (ApiAccessAuthenticateRequest) authentication.getPrincipal();

        ApiAccessAuthenticationToken authenticated = ApiAccessAuthenticationToken.authenticated(request, request.getAccessToken());

        String requestUri = request.getRequestUri();
        String applicationCode = "0";
        String method = request.getHttpMethod();
        // 先尝试uri是否匹配系统中存在的包含路径参数的api，如果存在的话就替换成统一的格式
        requestUri = attemptReplaceHasPathVariableUrl(requestUri);

        // 检查API是否无需认证和授权
        if (isMatchNoNeedAuthUri(requestUri, method)) {
            return authenticated;
        }

        LoginAuthenticationToken loginAuthentication = ((LoginAuthenticationToken) SecurityContextHolder.getContext().getAuthentication());
        boolean isAuthenticated = loginAuthentication != null && loginAuthentication.isAuthenticated();

        // 检查API是否只需认证并且当前用户是否认证成功
        if (isMatchJustNeedAuthenticationUri(requestUri, method) && isAuthenticated) {
            return authenticated;
        }

        // 如果还未认证，直接返回
        if (!isAuthenticated) {
            throw AuthException.of(HttpStatus.UNAUTHORIZED.value(), "访问资源需要先进行身份验证");
        }

        // 检查API是否需要授权
        if (isMatchNeedAuthorizationUri(requestUri, method)) {
            // 检查是否有API访问权
            Long userId = loginAuthentication.getLoginUser().getUserId();
            if (hasPermission(requestUri, applicationCode, method, userId)) {
                return authenticated;
            }
        }
        throw AuthException.of(HttpStatus.FORBIDDEN.value(), "权限不足，请联系管理员授权");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiAccessAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private boolean hasPermission(String requestUri, String applicationCode, String method, Long userId) {
        return userPermissionService.checkHasApiPermission(applicationCode, userId, requestUri, method);
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
     *
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchNeedAuthorizationUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNeedAuthorizationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证授权的资源
     *
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchNoNeedAuthUri(String requestUri, String method) {
        Map<String, String> cache = apiCacheHolder.getNoNeedAuthApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证的资源
     *
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
