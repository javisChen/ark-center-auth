package com.ark.center.auth.infra.authentication.login;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
public class LoginAuthenticationToken extends UsernamePasswordAuthenticationToken {

	private final String accessToken;

	public LoginAuthenticationToken(Object principal, String accessToken) {
		super(principal, "");
		this.accessToken = accessToken;
	}

	public String getAccessToken() {
		return accessToken;
	}
}
