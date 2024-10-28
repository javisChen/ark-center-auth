package com.ark.center.auth.infra.user.gateway.impl;

import com.ark.center.auth.domain.user.gateway.PermissionService;
import org.springframework.stereotype.Component;

@Component
public class PermissionServiceImpl implements PermissionService {


    @Override
    public boolean checkHasApiPermission(String applicationCode, String userCode, String requestUri, String method) {
        return false;
    }
}
