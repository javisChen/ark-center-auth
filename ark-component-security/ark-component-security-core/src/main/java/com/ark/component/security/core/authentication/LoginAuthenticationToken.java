package com.ark.component.security.core.authentication;

import com.ark.component.security.base.user.LoginUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * 登录认证成功令牌
 * 包含访问令牌、刷新令牌等信息
 */
public class LoginAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String accessToken;       // 访问令牌
    private final String refreshToken;      // 刷新令牌
    private final long expiresIn;          // 过期时间(秒)
    private final String tokenType;         // 令牌类型(Bearer)
    private final LoginUser loginUser;      // 登录用户信息

    public LoginAuthenticationToken(LoginUser loginUser, 
                                  String accessToken,
                                  String refreshToken,
                                  long expiresIn) {
        super(loginUser, loginUser.getPassword(), loginUser.getAuthorities());
        this.loginUser = loginUser;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.tokenType = "Bearer";
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public String getTokenType() {
        return tokenType;
    }

    public LoginUser getLoginUser() {
        return loginUser;
    }
}