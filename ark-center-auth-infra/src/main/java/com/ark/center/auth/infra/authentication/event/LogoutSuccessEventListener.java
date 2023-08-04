package com.ark.center.auth.infra.authentication.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@Slf4j
public class LogoutSuccessEventListener implements ApplicationListener<LogoutSuccessEvent> {

    @Override
    public void onApplicationEvent(LogoutSuccessEvent event) {
        log.info("用户登出成功：用户名 = {}，登录时间 = {}", event.getAuthentication().getName(), LocalDateTime.now());
    }
}