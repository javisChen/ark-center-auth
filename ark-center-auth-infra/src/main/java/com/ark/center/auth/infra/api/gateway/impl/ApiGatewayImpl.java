package com.ark.center.auth.infra.api.gateway.impl;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.user.gateway.ApiGateway;
import com.ark.center.auth.infra.api.converter.ApiConverter;
import com.ark.center.auth.infra.api.facade.ApiFacade;
import com.ark.center.iam.client.api.dto.ApiDetailsDTO;
import com.ark.center.iam.client.api.query.ApiQuery;
import com.ark.component.microservice.rpc.util.RpcUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ApiGatewayImpl implements ApiGateway {

    private final ApiFacade apiFacade;
    private final ApiConverter apiConverter;

    @Override
    public List<ApiMeta> retrieveApis() {
        // todo 认证中心自己做一层缓存，不要跟Iam耦合
        ApiQuery query = new ApiQuery();
        query.setStatus(1);
        List<ApiDetailsDTO> dtoList = RpcUtils.checkAndGetData(apiFacade.query(query));
        return apiConverter.toAuthMeta(dtoList);
    }

}
