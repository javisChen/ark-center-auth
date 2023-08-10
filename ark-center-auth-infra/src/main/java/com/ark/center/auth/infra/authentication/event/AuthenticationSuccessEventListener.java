package com.ark.center.auth.infra.authentication.event;

import com.ark.component.security.core.authentication.LoginAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@Slf4j
public class AuthenticationSuccessEventListener implements ApplicationListener<AuthenticationSuccessEvent> {

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        if (authentication instanceof LoginAuthenticationToken) {
            log.info("用户认证成功：用户名 = {}，登录时间 = {}", event.getAuthentication().getName(), LocalDateTime.now());
        }
    }
}