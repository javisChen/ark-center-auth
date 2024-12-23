package com.ark.center.auth.infra.authentication.login.mobile;

import com.ark.center.auth.client.login.constant.LoginMode;
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
    protected boolean supports(LoginMode loginMode) {
        return LoginMode.MOBILE.equals(loginMode);
    }
}
