package com.ark.center.auth.infra.authentication.api;

import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ApiAccessAuthenticationToken implements Authentication, CredentialsContainer {

    private final ApiAccessAuthenticateQuery authenticateRequest;
    private String accessToken;

    public ApiAccessAuthenticationToken(ApiAccessAuthenticateQuery authenticateRequest, String accessToken) {
        this.authenticateRequest = authenticateRequest;
        this.accessToken = accessToken;
    }


    public static ApiAccessAuthenticationToken unauthenticated(ApiAccessAuthenticateQuery principal, String accessToken) {
        return new ApiAccessAuthenticationToken(principal, accessToken);
    }

    public static ApiAccessAuthenticationToken authenticated(ApiAccessAuthenticateQuery principal, String accessToken) {
        return new ApiAccessAuthenticationToken(principal, accessToken);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return this.accessToken;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return String.format("[%s] [%s]", authenticateRequest.getHttpMethod(), authenticateRequest.getRequestUri());
    }

    @Override
    public Object getPrincipal() {
        return this.authenticateRequest;
    }

    @Override
    public void eraseCredentials() {
        this.accessToken = null;
    }
}
