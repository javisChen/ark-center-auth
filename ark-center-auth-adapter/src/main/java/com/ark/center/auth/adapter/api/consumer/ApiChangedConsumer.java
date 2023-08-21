package com.ark.center.auth.adapter.api.consumer;

import com.ark.center.auth.infra.authentication.cache.ApiCache;
import com.ark.center.iam.client.api.common.ApiMqInfo;
import com.ark.center.iam.client.api.dto.ApiChangedDTO;
import com.ark.component.mq.MQType;
import com.ark.component.mq.core.annotations.MQMessageListener;
import com.ark.component.mq.core.processor.SimpleMessageHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@MQMessageListener(
        mq = MQType.ROCKET,
        consumerGroup = ApiMqInfo.CG_APIS_CHANGED,
        topic = ApiMqInfo.TOPIC_IAM,
        tags = ApiMqInfo.TAG_APIS_CHANGED
)
@Component
@Slf4j
@RequiredArgsConstructor
public class ApiChangedConsumer extends SimpleMessageHandler<ApiChangedDTO> {

    private final ApiCache apiCache;

    @Override
    protected void handleMessage(String msgId, String sendId, ApiChangedDTO body, Object o) {
        log.info("Api发生变更 -> msgId = {}, sendId = {}, body = {}", msgId, sendId, body);
        // todo 当Api发生变更时，重新请求Iam获取最新的Api数据，暂不考虑数据量大的问题
        apiCache.refresh(false);
    }

}
