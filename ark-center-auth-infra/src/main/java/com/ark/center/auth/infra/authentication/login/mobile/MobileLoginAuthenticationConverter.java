package com.ark.center.auth.infra.authentication.login.mobile;

import com.ark.center.auth.client.authentication.command.MobileLoginAuthenticateRequest;
import com.ark.center.auth.client.authentication.constant.AuthStrategy;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationConverter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class MobileLoginAuthenticationConverter extends LoginAuthenticationConverter<MobileLoginAuthenticateRequest> {

    @Override
    protected Authentication doConvert(MobileLoginAuthenticateRequest authenticateRequest) {
        return MobileAuthenticationToken
                .unauthenticated(authenticateRequest.getMobile(), authenticateRequest.getCaptcha());
    }

    @Override
    protected boolean supports(AuthStrategy authStrategy) {
        return AuthStrategy.SMS.equals(authStrategy);
    }
}
