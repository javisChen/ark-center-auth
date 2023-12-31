package com.ark.center.auth.infra.authentication.token.generator;


import com.ark.center.auth.infra.authentication.token.UserToken;
import com.ark.component.security.base.user.LoginUser;

public interface UserTokenGenerator {

    UserToken generate(LoginUser loginUser);
}
