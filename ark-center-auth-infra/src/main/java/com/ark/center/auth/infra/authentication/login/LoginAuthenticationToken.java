package com.ark.center.auth.infra.authentication.login;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
public class LoginAuthenticationToken extends UsernamePasswordAuthenticationToken {


	public LoginAuthenticationToken(Object principal, Object credentials) {
		super(principal, credentials);
	}

	public LoginAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
	}
}
