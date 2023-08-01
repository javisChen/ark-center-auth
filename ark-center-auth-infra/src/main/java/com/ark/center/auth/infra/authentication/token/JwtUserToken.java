package com.ark.center.auth.infra.authentication.token;

import lombok.Getter;

import java.util.Map;

@Getter
public class JwtUserToken extends AbstractUserToken {

    private final Map<String, Object> headers;

    private final Map<String, Object> claims;
    public JwtUserToken(String tokenValue, Map<String, Object> headers, Map<String, Object> claims) {
        super(tokenValue);
        this.headers = headers;
        this.claims = claims;
    }
}
