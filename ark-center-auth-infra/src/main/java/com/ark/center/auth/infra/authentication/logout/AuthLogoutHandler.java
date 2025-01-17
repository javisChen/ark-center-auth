package com.ark.center.auth.infra.authentication.logout;

import com.ark.center.auth.infra.authentication.common.CacheKeyManager;
import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.component.cache.CacheService;
import com.ark.component.dto.ServerResponse;
import com.ark.component.security.base.user.AuthUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import java.io.IOException;

@Slf4j
public class AuthLogoutHandler implements LogoutSuccessHandler, LogoutHandler {

    private final CacheService cacheService;
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    public AuthLogoutHandler(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        if (authentication == null) {
            return;
        }

        AuthUser user = (AuthUser) authentication.getPrincipal();

        String accessToken = bearerTokenResolver.resolve(request);

        // 删除用户认证信息缓存
        cacheService.del(CacheKeyManager.createAccessTokenKey(accessToken));

        cacheService.del(CacheKeyManager.createUserIdKey(user.getUserId()));

    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        ResponseUtils.write(ServerResponse.ok(), response, HttpStatus.SC_OK);
    }
}
