package com.ark.center.auth.infra.authentication.api;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class ApiAccessAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public ApiAccessAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public static ApiAccessAuthenticationToken unauthenticated(Object principal) {
        return new ApiAccessAuthenticationToken(principal, null);
    }

    public static ApiAccessAuthenticationToken authenticated(Object principal) {
        return new ApiAccessAuthenticationToken(principal, null);
    }

}
