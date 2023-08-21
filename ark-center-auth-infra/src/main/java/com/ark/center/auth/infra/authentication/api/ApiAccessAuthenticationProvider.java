package com.ark.center.auth.infra.authentication.api;

import com.ark.center.auth.domain.user.AuthUserApiPermission;
import com.ark.center.auth.domain.user.service.UserPermissionService;
import com.ark.center.auth.infra.api.support.ApiCommonUtils;
import com.ark.center.auth.infra.authentication.cache.ApiCache;
import com.ark.component.security.base.user.LoginUser;
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

    private final ApiCache apiCache;

    private final UserPermissionService userPermissionService;


    public ApiAccessAuthenticationProvider(ApiCache apiCache, UserPermissionService userPermissionService) {
        this.apiCache = apiCache;
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
            log.warn("用户未登录或凭证已失效");
            throw AuthException.of(HttpStatus.UNAUTHORIZED.value(), "访问资源需要先进行身份验证");
        }

        // 检查API是否需要授权
        if (isMatchNeedAuthorizationUri(requestUri, method)) {
            // 检查是否有API访问权
            if (hasPermission(requestUri, method, loginAuthentication.getLoginUser())) {
                return authenticated;
            }
        }
        log.warn("请检查用户角色是否已经对该[{} {}]进行授权", requestUri, method);
        throw AuthException.of(HttpStatus.FORBIDDEN.value(), "权限不足，请联系管理员授权");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiAccessAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private boolean hasPermission(String requestUri, String method, LoginUser user) {
        if (user.getUserCode().equals("SuperAdmin")) {
            return true;
        }
        List<AuthUserApiPermission> apiPermissions = userPermissionService.queryUserApiPermission(user.getUserId());
        return apiPermissions.stream()
                .anyMatch(item -> pathMatcher.match(item.getUri(), requestUri)
                        && item.getMethod().equals(method));
    }

    public String attemptReplaceHasPathVariableUrl(String requestUri) {
        List<String> hasPathVariableApiCache = apiCache.getHasPathVariableApiCache();
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
        Map<String, String> cache = apiCache.getNeedAuthorizationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证授权的资源
     *
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchNoNeedAuthUri(String requestUri, String method) {
        Map<String, String> cache = apiCache.getNoNeedAuthApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    /**
     * 尝试匹配无需认证的资源
     *
     * @return 匹配成功=true，不成功=false
     */
    public boolean isMatchJustNeedAuthenticationUri(String requestUri, String method) {
        Map<String, String> cache = apiCache.getNeedAuthenticationApiCache();
        return isMatchUri(cache, requestUri, method);
    }

    private boolean isMatchUri(Map<String, String> cache, String requestUri, String method) {
        if (MapUtils.isEmpty(cache)) {
            return false;
        }
        return cache.get(ApiCommonUtils.createKey(requestUri, method)) != null;
    }


}
