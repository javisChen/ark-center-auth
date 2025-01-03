package com.ark.center.auth.infra.user.gateway.impl;

import com.ark.component.security.base.user.AuthUser;
import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.cache.UserApiPermissionCache;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.center.auth.infra.user.facade.UserFacade;
import com.ark.center.auth.infra.user.facade.UserPermissionFacade;
import com.ark.center.iam.client.user.dto.UserAuthDTO;
import com.ark.center.iam.client.user.query.UserPermissionQuery;
import com.ark.center.iam.client.user.query.UserQuery;
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
        UserQuery userQuery = new UserQuery();
        userQuery.setMobile(mobile);
        UserAuthDTO userAuthDTO = RpcUtils.checkAndGetData(userFacade.getUserForAuth(userQuery));
        return userConverter.toAuthUser(userAuthDTO);
    }

    @Override
    public AuthUser retrieveUserByUsername(String username) {
        UserQuery userQuery = new UserQuery();
        userQuery.setUsername(username);
        UserAuthDTO userAuthDTO = RpcUtils.checkAndGetData(userFacade.getUserForAuth(userQuery));
        return userConverter.toAuthUser(userAuthDTO);
    }

    @Override
    public Boolean checkHasPermission(String requestUri, String applicationCode, String method, Long userId) {
        UserPermissionQuery userPermissionQuery = new UserPermissionQuery();
        userPermissionQuery.setRequestUri(requestUri);
        userPermissionQuery.setApplicationCode(applicationCode);
        userPermissionQuery.setMethod(method);
        userPermissionQuery.setUserId(userId);
        return RpcUtils.checkAndGetData(userPermissionFacade.hasApiPermission(userPermissionQuery));
    }

    @Override
    public List<AuthUserApiPermission> queryUserApiPermissions(Long userId) {
        return userApiPermissionCache.get(userId);
    }
}
