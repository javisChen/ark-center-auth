package com.ark.center.auth.adapter.user.consumer;

import com.ark.center.auth.infra.authentication.cache.UserApiPermissionCache;
import com.ark.center.iam.model.user.common.UserMqInfo;
import com.ark.center.iam.model.user.dto.UserApiPermissionChangedDTO;
import com.ark.component.mq.MQType;
import com.ark.component.mq.core.annotations.MQMessageListener;
import com.ark.component.mq.core.processor.SimpleMessageHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@MQMessageListener(
        mq = MQType.ROCKET,
        consumerGroup = UserMqInfo.CG_USER_API_PERMS,
        topic = UserMqInfo.TOPIC_IAM,
        tags = UserMqInfo.TAG_USER_API_PERMS
)
@Component
@Slf4j
@RequiredArgsConstructor
public class UserPermissionChangedConsumer extends SimpleMessageHandler<UserApiPermissionChangedDTO> {

    private final UserApiPermissionCache userApiPermissionCache;

    @Override
    protected void handleMessage(String msgId, String sendId, UserApiPermissionChangedDTO body, Object o) {
        log.info("用户Api权限发生变更 -> msgId = {}, sendId = {}, body = {}", msgId, sendId, body);
        userApiPermissionCache.refresh(body.getUserId());
    }

}
