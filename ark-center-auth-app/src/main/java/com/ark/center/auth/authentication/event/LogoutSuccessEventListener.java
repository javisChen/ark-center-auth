package com.ark.center.auth.authentication.event;

import com.ark.center.auth.client.mq.AuthConst;
import com.ark.center.auth.client.mq.logout.UserLogoutMQConst;
import com.ark.center.auth.client.mq.logout.UserLogoutMessage;
import com.ark.component.mq.MsgBody;
import com.ark.component.mq.SendConfirm;
import com.ark.component.mq.SendResult;
import com.ark.component.mq.integration.MessageTemplate;
import com.ark.component.security.base.user.AuthUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@Slf4j
@RequiredArgsConstructor
public class LogoutSuccessEventListener implements ApplicationListener<LogoutSuccessEvent> {

    private final MessageTemplate messageTemplate;

    @Override
    public void onApplicationEvent(LogoutSuccessEvent event) {

        log.info("User logout successfully：{}, time = {}", event.getAuthentication(), LocalDateTime.now());

        AuthUser user = (AuthUser) event.getAuthentication().getPrincipal();

        publishMessage(user);
    }

    private void publishMessage(AuthUser user) {
        UserLogoutMessage message = new UserLogoutMessage(user.getUserId(), LocalDateTime.now());
        messageTemplate.asyncSend(AuthConst.TOPIC_AUTH, UserLogoutMQConst.USER_LOGOUT_EVENT_TAG, MsgBody.of(message), new SendConfirm() {
            @Override
            public void onSuccess(SendResult sendResult) {
                log.info("The user logout event was published successfully, result = {}", sendResult);
            }

            @Override
            public void onException(SendResult sendResult) {
                log.info("The user logout event failed to be published, result = {}", sendResult);
            }
        });
    }
}