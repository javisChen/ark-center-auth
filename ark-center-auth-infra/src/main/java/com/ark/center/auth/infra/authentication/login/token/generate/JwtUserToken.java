package com.ark.center.auth.infra.authentication.login.token.generate;

import java.util.Map;

public class JwtUserToken extends AbstractUserToken {
    private final Map<String, Object> headers;

    private final Map<String, Object> claims;
    protected JwtUserToken(String tokenValue, Map<String, Object> headers, Map<String, Object> claims) {
        super(tokenValue);
        this.headers = headers;
        this.claims = claims;
    }
}
