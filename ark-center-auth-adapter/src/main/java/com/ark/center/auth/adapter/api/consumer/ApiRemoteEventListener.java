package com.ark.center.auth.adapter.api.consumer;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import com.ark.center.auth.infra.user.gateway.ApiGateway;
import com.ark.center.iam.client.api.event.ApiChangeEventDTO;
import com.ark.center.iam.client.api.enums.ApiChangeType;
import com.ark.center.iam.client.contants.IamMQConst;
import com.ark.component.mq.MQType;
import com.ark.component.mq.core.annotations.MQMessageListener;
import com.ark.component.mq.core.processor.SimpleMessageHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static com.ark.center.iam.client.api.enums.ApiChangeType.CREATED;
import static com.ark.center.iam.client.api.enums.ApiChangeType.DELETED;
import static com.ark.center.iam.client.api.enums.ApiChangeType.STATUS_CHANGED;
import static com.ark.center.iam.client.api.enums.ApiChangeType.UPDATED;

@MQMessageListener(
        mq = MQType.ROCKET,
        consumerGroup = IamMQConst.CG_API_CHANGED,
        topic = IamMQConst.TOPIC_IAM,
        tags = IamMQConst.TAG_API_CHANGED
)
@Component
@Slf4j
@RequiredArgsConstructor
public class ApiRemoteEventListener extends SimpleMessageHandler<ApiChangeEventDTO> {

    private final ApiGateway apiGateway;
    private final ApiResourceRepository apiResourceRepository;

    @Override
    protected void handleMessage(String msgId, String sendId, ApiChangeEventDTO event, Object o) {
        log.info("Received API change event -> msgId = {}, sendId = {}, event = {}", msgId, sendId, event);
        
        try {
            switch (event.getChangeType()) {
                case DELETED -> {
                    ApiMeta api = apiGateway.getApi(event.getApiId());
                    if (api != null) {
                        apiResourceRepository.removeApi(api);
                        log.info("API deleted, cache cleared: apiId={}", event.getApiId());
                    }
                }
                case CREATED, UPDATED, STATUS_CHANGED -> {
                    ApiMeta api = apiGateway.getApi(event.getApiId());
                    if (api != null) {
                        if (api.getStatus() == 2) { // 2表示已禁用
                            apiResourceRepository.removeApi(api);
                            log.info("API disabled, cache removed: apiId={}", event.getApiId());
                        } else {
                            apiResourceRepository.updateApi(api);
                            log.info("API updated, cache refreshed: apiId={}", event.getApiId());
                        }
                    } else {
                        log.warn("API not found, cannot update cache: apiId={}", event.getApiId());
                    }
                }
                default -> log.warn("Unhandled API change type: {}", event.getChangeType());
            }
        } catch (Exception e) {
            log.error("Failed to process API change event: {}", e.getMessage(), e);
        }
    }
}
