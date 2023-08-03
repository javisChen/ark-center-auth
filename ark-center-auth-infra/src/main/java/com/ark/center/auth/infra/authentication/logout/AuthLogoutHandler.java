package com.ark.center.auth.infra.authentication.logout;

import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.center.auth.infra.authentication.token.repository.RedisKeyUtils;
import com.ark.component.cache.CacheService;
import com.ark.component.dto.ServerResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

public class AuthLogoutHandler implements LogoutSuccessHandler, LogoutHandler {

    private final CacheService cacheService;
    private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    public AuthLogoutHandler(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        if (authentication == null) {
            return;
        }

        LoginUser user = (LoginUser) authentication.getPrincipal();

        String accessToken = bearerTokenResolver.resolve(request);

        cacheService.remove(RedisKeyUtils.createAccessTokenKey(accessToken));

        cacheService.remove(RedisKeyUtils.createUserIdKey(user.getUserId()));

    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        ResponseUtils.write(ServerResponse.ok(), response, HttpStatus.SC_OK);
    }
}
