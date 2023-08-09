package com.ark.center.auth.domain.user.gateway;

import com.ark.center.auth.domain.user.AuthUser;

public interface UserGateway {

    AuthUser retrieveUserByPhone(String phone);

    AuthUser retrieveUserByUsername(String username);

    Boolean checkHasPermission(String requestUri, String applicationCode, String method, Long userId);
}
