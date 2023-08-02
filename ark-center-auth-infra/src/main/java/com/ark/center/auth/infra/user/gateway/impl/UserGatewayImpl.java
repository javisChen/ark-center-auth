package com.ark.center.auth.infra.user.gateway.impl;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.center.auth.infra.user.facade.UserFacade;
import com.ark.center.iam.client.user.dto.UserInnerDTO;
import com.ark.center.iam.client.user.query.UserQry;
import com.ark.component.microservice.rpc.util.RpcUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserGatewayImpl implements UserGateway {

    private final UserFacade userFacade;

    private final UserConverter userConverter;

    @Override
    public AuthUser retrieveUserByPhone(String phone) {
        UserQry userQry = new UserQry();
        userQry.setPhone(phone);
        UserInnerDTO userInnerDTO = RpcUtils.checkAndGetData(userFacade.getUser(userQry));
        return userConverter.toAuthUser(userInnerDTO);
    }

    @Override
    public AuthUser retrieveUserByUserName(String userName) {
        UserQry userQry = new UserQry();
        userQry.setUsername(userName);
        UserInnerDTO userInnerDTO = RpcUtils.checkAndGetData(userFacade.getUser(userQry));
        return userConverter.toAuthUser(userInnerDTO);
    }

    @Override
    public Boolean checkHasPermission(String requestUri, String applicationCode, String method, String userCode) {
        return null;
    }
}
