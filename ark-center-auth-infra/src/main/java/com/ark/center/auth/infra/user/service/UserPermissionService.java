package com.ark.center.auth.infra.user.service;

import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.gateway.UserGateway;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserPermissionService {

    private final UserGateway userGateway;

    public boolean checkHasApiPermission(String applicationCode, Long userId, String requestUri, String method) {
        return userGateway.checkHasPermission(requestUri, applicationCode, method, userId);
    }

    public List<AuthUserApiPermission> queryUserApiPermission(Long userId) {
        return userGateway.queryUserApiPermissions(userId);
    }
}
