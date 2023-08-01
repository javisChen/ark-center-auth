package com.ark.center.auth.infra.authentication.login;

import com.ark.center.auth.infra.authentication.token.UserToken;
import com.ark.center.auth.infra.authentication.token.generate.UserTokenGenerator;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

public class LoginAuthenticationProvider extends DaoAuthenticationProvider {

    private final UserTokenGenerator userTokenGenerator;

    public LoginAuthenticationProvider(UserTokenGenerator userTokenGenerator) {
        this.userTokenGenerator = userTokenGenerator;
    }

    @Override
    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
        LoginUser loginUser = (LoginUser) user;
        UserToken userToken = this.userTokenGenerator.generate(loginUser);
        return new LoginAuthenticationToken(loginUser, userToken.getTokenValue());
    }

}