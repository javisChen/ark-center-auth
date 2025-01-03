package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.component.security.base.user.AuthUser;

import java.util.List;

public interface UserGateway {

    AuthUser retrieveUserByMobile(String mobile);

    AuthUser retrieveUserByUsername(String username);

    Boolean checkHasPermission(String requestUri, String applicationCode, String method, Long userId);

    List<AuthUserApiPermission> queryUserApiPermissions(Long userId);
}
