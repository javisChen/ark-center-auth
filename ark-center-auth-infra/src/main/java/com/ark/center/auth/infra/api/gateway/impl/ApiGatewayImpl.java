package com.ark.center.auth.infra.api.gateway.impl;

import com.ark.center.auth.domain.api.AuthApi;
import com.ark.center.auth.domain.user.gateway.ApiGateway;
import com.ark.center.auth.infra.api.converter.ApiConverter;
import com.ark.center.auth.infra.api.facade.ApiFacade;
import com.ark.center.iam.client.api.dto.ApiDetailsDTO;
import com.ark.center.iam.client.api.query.ApiQry;
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
    public List<AuthApi> retrieveApis() {
        List<ApiDetailsDTO> dtoList = RpcUtils.checkAndGetData(apiFacade.queryApis(new ApiQry()));
        return apiConverter.toAuthApi(dtoList);
    }

}
