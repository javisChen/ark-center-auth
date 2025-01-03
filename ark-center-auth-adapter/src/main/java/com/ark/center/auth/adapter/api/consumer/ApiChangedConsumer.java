package com.ark.center.auth.adapter.api.consumer;

import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import com.ark.center.iam.client.api.dto.ApiChangedDTO;
import com.ark.center.iam.client.contants.IamMQConst;
import com.ark.component.mq.MQType;
import com.ark.component.mq.core.annotations.MQMessageListener;
import com.ark.component.mq.core.processor.SimpleMessageHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@MQMessageListener(
        mq = MQType.ROCKET,
        consumerGroup = IamMQConst.CG_API_CHANGED,
        topic = IamMQConst.TOPIC_IAM,
        tags = IamMQConst.TAG_API_CHANGED
)
@Component
@Slf4j
@RequiredArgsConstructor
public class ApiChangedConsumer extends SimpleMessageHandler<ApiChangedDTO> {

    private final ApiResourceRepository apiResourceRepository;

    @Override
    protected void handleMessage(String msgId, String sendId, ApiChangedDTO body, Object o) {
        log.info("Api发生变更 -> msgId = {}, sendId = {}, body = {}", msgId, sendId, body);
        // todo 当Api发生变更时，重新请求Iam获取最新的Api数据，暂不考虑数据量大的问题
        apiResourceRepository.refresh(false);
    }

}
