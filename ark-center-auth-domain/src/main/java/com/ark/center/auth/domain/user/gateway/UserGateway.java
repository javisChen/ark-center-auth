package com.ark.center.auth.domain.user.gateway;

import com.ark.center.auth.domain.user.AuthUser;

public interface UserGateway {

    AuthUser retrieveUserByPhone(String phone);

    AuthUser retrieveUserByUserName(String userName);

    Boolean checkHasPermission(String requestUri, String applicationCode, String method, String userCode);
}
