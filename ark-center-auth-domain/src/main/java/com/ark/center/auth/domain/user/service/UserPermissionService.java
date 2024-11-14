package com.ark.center.auth.domain.user.service;

import com.ark.center.auth.domain.user.AuthUserApiPermission;
import com.ark.center.auth.domain.user.gateway.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserPermissionService {

    private final UserService userGateway;

    public boolean checkHasApiPermission(String applicationCode, Long userId, String requestUri, String method) {
        return userGateway.checkHasPermission(requestUri, applicationCode, method, userId);
    }

    public List<AuthUserApiPermission> queryUserApiPermission(Long userId) {
        return userGateway.queryUserApiPermissions(userId);
    }
}
