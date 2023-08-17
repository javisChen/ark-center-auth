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
import java.util.List;

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

        // 清除用户Api权限缓存
        Long userId = loginAuthenticationToken.getLoginUser().getUserId();
        userApiPermissionCache.remove(userId);
        log.info("用户Api权限清除成功");

        List<String> userApiList = userApiPermissionCache.get(userId);
        log.info("用户Api权限: {} \n", String.join("\n", userApiList));

    }
}