package com.ark.center.auth.domain.user.service;

import com.ark.center.auth.domain.user.gateway.PermissionGateway;
import org.springframework.stereotype.Service;

@Service
public class UserPermissionService {

    private PermissionGateway permissionGateway;

    public boolean checkHasApiPermission(String applicationCode, String userCode, String requestUri, String method) {
        return permissionGateway.checkHasApiPermission(applicationCode, userCode, requestUri, method);
    }
}
