package com.ark.center.auth.infra.authentication.login.sms;

import com.ark.center.auth.infra.authentication.login.LoginAuthenticationConverter;
import com.ark.center.auth.infra.authentication.login.LoginMode;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@Slf4j
public class SmsLoginAuthenticationConverter extends LoginAuthenticationConverter<SmsLoginAuthenticateRequest> {

    @Override
    protected void preChecks(SmsLoginAuthenticateRequest authenticateRequest) {

    }

    @Override
	protected Authentication internalConvert(HttpServletRequest request, SmsLoginAuthenticateRequest authenticateRequest) {
		return UsernamePasswordAuthenticationToken
				.unauthenticated(authenticateRequest.getMobile(), authenticateRequest.getCode());
	}

    @Override
    protected LoginMode loginMode() {
        return LoginMode.MOBILE_SMS;
    }
}
