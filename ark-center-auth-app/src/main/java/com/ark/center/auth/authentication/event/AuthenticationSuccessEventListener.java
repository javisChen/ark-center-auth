package com.ark.center.auth.authentication.event;

import com.ark.center.auth.infra.authentication.cache.UserApiPermissionCache;
import com.ark.component.security.core.authentication.AuthenticatedToken;
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
        if (authentication instanceof AuthenticatedToken loginAuthenticationToken) {
            handlerForLoginSuccess(event, loginAuthenticationToken);
        }
    }

    private void handlerForLoginSuccess(AuthenticationSuccessEvent event, AuthenticatedToken loginAuthenticationToken) {
        log.info("User successfully authenticated: {}, time = {}", loginAuthenticationToken, LocalDateTime.now());
        Long userId = loginAuthenticationToken.getAuthUser().getUserId();
        // 刷新权限缓存
        userApiPermissionCache.refresh(userId);

    }
}