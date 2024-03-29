package com.ark.center.auth.infra.user.gateway.impl;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.AuthUserApiPermission;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.cache.UserApiPermissionCache;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.center.auth.infra.user.facade.UserFacade;
import com.ark.center.auth.infra.user.facade.UserPermissionFacade;
import com.ark.center.iam.model.user.dto.UserInnerDTO;
import com.ark.center.iam.model.user.query.UserPermissionQuery;
import com.ark.center.iam.model.user.query.UserQuery;
import com.ark.component.microservice.rpc.util.RpcUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class UserGatewayImpl implements UserGateway {

    private final UserFacade userFacade;
    private final UserPermissionFacade userPermissionFacade;
    private final UserConverter userConverter;
    private final UserApiPermissionCache userApiPermissionCache;

    @Override
    public AuthUser retrieveUserByMobile(String mobile) {
        UserQuery userQry = new UserQuery();
        userQry.setMobile(mobile);
        UserInnerDTO userInnerDTO = RpcUtils.checkAndGetData(userFacade.queryBasicInfo(userQry));
        return userConverter.toAuthUser(userInnerDTO);
    }

    @Override
    public AuthUser retrieveUserByUsername(String username) {
        UserQuery userQry = new UserQuery();
        userQry.setUsername(username);
        UserInnerDTO userInnerDTO = RpcUtils.checkAndGetData(userFacade.queryBasicInfo(userQry));
        return userConverter.toAuthUser(userInnerDTO);
    }

    @Override
    public Boolean checkHasPermission(String requestUri, String applicationCode, String method, Long userId) {
        UserPermissionQuery userPermissionQry = new UserPermissionQuery();
        userPermissionQry.setRequestUri(requestUri);
        userPermissionQry.setApplicationCode(applicationCode);
        userPermissionQry.setMethod(method);
        userPermissionQry.setUserId(userId);
        return RpcUtils.checkAndGetData(userPermissionFacade.checkApiHasPermission(userPermissionQry));
    }

    @Override
    public List<AuthUserApiPermission> queryUserApiPermissions(Long userId) {
        return userApiPermissionCache.get(userId);
    }
}
