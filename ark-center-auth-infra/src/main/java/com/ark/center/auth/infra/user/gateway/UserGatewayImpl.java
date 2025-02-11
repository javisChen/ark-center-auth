package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.iam.client.user.dto.UserApiPermissionDTO;
import com.ark.component.security.base.authentication.AuthUser;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.center.auth.infra.user.facade.UserFacade;
import com.ark.center.auth.infra.user.facade.UserPermissionFacade;
import com.ark.center.iam.client.user.dto.UserAuthDTO;
import com.ark.center.iam.client.user.query.UserQuery;
import com.ark.component.microservice.rpc.util.RpcUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 用户远程服务调用实现
 */
@Component
@RequiredArgsConstructor
public class UserGatewayImpl implements UserGateway {

    private final UserFacade userFacade;
    private final UserPermissionFacade userPermissionFacade;
    private final UserConverter userConverter;

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
    public List<AuthUserApiPermission> queryUserApiPermissions(Long userId) {
        List<UserApiPermissionDTO> apiList = RpcUtils.checkAndGetData(userPermissionFacade.queryUserApiPermissions(userId));
        return userConverter.toAuthUserApiPermission(apiList);
    }
}
