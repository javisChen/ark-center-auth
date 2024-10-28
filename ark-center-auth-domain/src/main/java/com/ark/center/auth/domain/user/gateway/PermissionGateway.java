package com.ark.center.auth.domain.user.gateway;

public interface PermissionService {
    boolean checkHasApiPermission(String applicationCode, String userCode, String requestUri, String method);
}
