package com.ark.center.auth.infra.authentication.login.token.generate;


import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.center.auth.infra.authentication.login.token.UserToken;

public interface UserTokenGenerator {

    UserToken generate(LoginUser loginUser);
}
