package com.ark.center.auth.adapter.user.consumer;

import com.ark.center.iam.client.user.common.UserMqConst;
import com.ark.center.iam.client.user.dto.UserApiPermissionChangedDTO;
import com.ark.component.mq.MQType;
import com.ark.component.mq.core.annotations.MQMessageListener;
import com.ark.component.mq.core.processor.SimpleMessageHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@MQMessageListener(
        mq = MQType.ROCKET,
        consumerGroup = UserMqConst.CG_USER_API_PERMS,
        topic = UserMqConst.TOPIC_IAM,
        tags = UserMqConst.TAG_USER_API_PERMS
)
@Component
@Slf4j
@RequiredArgsConstructor
public class UserPermissionChangedConsumer extends SimpleMessageHandler<UserApiPermissionChangedDTO> {

    @Override
    protected void handleMessage(String msgId, String sendId, UserApiPermissionChangedDTO body, Object o) {
        log.info("用户Api权限发生变更 -> msgId = {}, sendId = {}, body = {}", msgId, sendId, body);
    }
}
