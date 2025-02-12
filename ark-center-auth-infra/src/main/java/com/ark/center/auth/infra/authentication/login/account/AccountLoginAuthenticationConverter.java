package com.ark.center.auth.infra.authentication.login.account;

import cn.hutool.crypto.digest.DigestUtil;
import com.ark.center.auth.client.authentication.command.AccountLoginAuthenticateRequest;
import com.ark.center.auth.client.authentication.common.AuthStrategy;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticationConverter;
import com.ark.component.security.core.common.SecurityConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AccountLoginAuthenticationConverter extends LoginAuthenticationConverter<AccountLoginAuthenticateRequest> {

    @Override
    protected Authentication doConvert(AccountLoginAuthenticateRequest authenticateRequest) {
        authenticateRequest.setPassword(DigestUtil.md5Hex(authenticateRequest.getPassword()) + SecurityConstants.PASSWORD_SALT);
        return AccountAuthenticationToken
                .unauthenticated(authenticateRequest.getUsername(), authenticateRequest.getPassword());
    }

    @Override
    protected boolean supports(AuthStrategy authStrategy) {
        return authStrategy.equals(AuthStrategy.PWD);
    }
}
