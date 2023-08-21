package com.ark.center.auth.infra.authentication.event;

import com.ark.center.auth.infra.authentication.cache.UserApiPermissionCache;
import com.ark.component.security.core.authentication.LoginAuthenticationToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationSuccessEventListener implements ApplicationListener<AuthenticationSuccessEvent> {

    private final UserApiPermissionCache userApiPermissionCache;

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        if (authentication instanceof LoginAuthenticationToken loginAuthenticationToken) {
            handlerForLoginSuccess(event, loginAuthenticationToken);
        }
    }

    private void handlerForLoginSuccess(AuthenticationSuccessEvent event, LoginAuthenticationToken loginAuthenticationToken) {
        log.info("用户认证成功: 用户名 = {}，登录时间 = {}", loginAuthenticationToken.getName(), LocalDateTime.now());

        Long userId = loginAuthenticationToken.getLoginUser().getUserId();

        // 刷新权限缓存
        userApiPermissionCache.refresh(userId);

    }
}