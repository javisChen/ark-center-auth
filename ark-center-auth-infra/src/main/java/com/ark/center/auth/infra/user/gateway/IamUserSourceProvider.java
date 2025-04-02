package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.component.security.base.authentication.AuthUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * IAM默认用户源提供者
 */
@Component
@RequiredArgsConstructor
public class IamUserSourceProvider implements UserSourceProvider {

    private final UserGateway userGateway;

    @Override
    public AuthUser retrieveUserByUsername(String username, Authentication authentication) {
        return userGateway.retrieveUserByUsername(username);
    }

    @Override
    public AuthUser retrieveUserByMobile(String mobile, Authentication authentication) {
        return userGateway.retrieveUserByMobile(mobile);
    }

    @Override
    public Set<AppCode> getSupportedAppCodes() {
        return Set.of(AppCode.OPERATION_ADMIN, AppCode.PLATFORM_ADMIN);
    }

} 