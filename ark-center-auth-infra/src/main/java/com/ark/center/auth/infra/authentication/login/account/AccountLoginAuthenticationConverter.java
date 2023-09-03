package com.ark.center.auth.infra.authentication.login.account;

import cn.hutool.crypto.digest.DigestUtil;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationConverter;
import com.ark.center.auth.infra.authentication.login.LoginMode;
import com.ark.component.security.core.config.SecurityConstants;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@Slf4j
public class AccountLoginAuthenticationConverter extends LoginAuthenticationConverter<AccountLoginAuthenticateRequest> {

    @Override
    protected void preChecks(AccountLoginAuthenticateRequest authenticateRequest) {

    }

    @Override
	protected Authentication internalConvert(HttpServletRequest request, AccountLoginAuthenticateRequest authenticateRequest) {
		 authenticateRequest.setPassword(DigestUtil.md5Hex(authenticateRequest.getPassword()) + SecurityConstants.PASSWORD_SALT);
		return UsernamePasswordAuthenticationToken
				.unauthenticated(authenticateRequest.getUsername(), authenticateRequest.getPassword());
	}

    @Override
    protected LoginMode loginMode() {
        return LoginMode.ACCOUNT;
    }
}
