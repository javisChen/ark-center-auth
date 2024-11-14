package com.ark.center.auth.domain.user.gateway;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.AuthUserApiPermission;

import java.util.List;

public interface UserService {

    AuthUser retrieveUserByMobile(String mobile);

    AuthUser retrieveUserByUsername(String username);

    Boolean checkHasPermission(String requestUri, String applicationCode, String method, Long userId);

    List<AuthUserApiPermission> queryUserApiPermissions(Long userId);
}
