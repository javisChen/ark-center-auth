package com.ark.center.auth.infra.authentication.api;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ApiAccessAuthenticationToken implements Authentication, CredentialsContainer {

    private final ApiAccessAuthenticateRequest authenticateRequest;
    private String accessToken;

    public ApiAccessAuthenticationToken(ApiAccessAuthenticateRequest authenticateRequest, String accessToken) {
        this.authenticateRequest = authenticateRequest;
        this.accessToken = accessToken;
    }


    public static ApiAccessAuthenticationToken unauthenticated(ApiAccessAuthenticateRequest principal, String accessToken) {
        return new ApiAccessAuthenticationToken(principal, accessToken);
    }

    public static ApiAccessAuthenticationToken authenticated(ApiAccessAuthenticateRequest principal, String accessToken) {
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
