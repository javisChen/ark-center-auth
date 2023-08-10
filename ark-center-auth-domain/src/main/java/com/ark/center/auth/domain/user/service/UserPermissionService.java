package com.ark.center.auth.domain.user.service;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserPermissionService {


    private final UserGateway userGateway;

    public boolean checkHasApiPermission(String applicationCode, Long userId, String requestUri, String method) {
        return userGateway.checkHasPermission(requestUri, applicationCode, method, userId);
    }
}
