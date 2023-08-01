package com.ark.center.auth.infra.authentication.login;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class LoginAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String accessToken;
    private final LoginUser loginUser;

    public LoginAuthenticationToken(LoginUser loginUser, String accessToken) {
        super(loginUser, loginUser.getPassword());
        this.accessToken = accessToken;
        this.loginUser = loginUser;
    }

    public LoginAuthenticationToken(LoginUser loginUser, String accessToken, Collection<? extends GrantedAuthority> authorities) {
        super(loginUser, loginUser.getPassword(), authorities);
        this.accessToken = accessToken;
        this.loginUser = loginUser;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public LoginUser getLoginUser() {
        return loginUser;
    }

}
