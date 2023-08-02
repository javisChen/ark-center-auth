package com.ark.center.auth.infra.user.gateway.impl;

import com.ark.center.auth.domain.user.gateway.PermissionGateway;

public class PermissionGatewayImpl implements PermissionGateway {


    @Override
    public boolean checkHasApiPermission(String applicationCode, String userCode, String requestUri, String method) {
        return false;
    }
}
