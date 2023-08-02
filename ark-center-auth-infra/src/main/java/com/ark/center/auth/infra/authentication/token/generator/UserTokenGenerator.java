package com.ark.center.auth.infra.authentication.token.generator;


import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.center.auth.infra.authentication.token.UserToken;

public interface UserTokenGenerator {

    UserToken generate(LoginUser loginUser);
}
