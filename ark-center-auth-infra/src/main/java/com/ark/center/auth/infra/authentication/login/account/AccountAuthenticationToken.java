package com.ark.center.auth.infra.authentication.login.account;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.util.Collection;

@Getter
public class AccountAuthenticationToken extends AbstractAuthenticationToken {

	private final String username;

	private String password;

	public AccountAuthenticationToken(String username, String password) {
		super(null);
		this.username = username;
		this.password = password;
		setAuthenticated(false);
	}

	public AccountAuthenticationToken(String username, String password,
									  Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.username = username;
		this.password = password;
		super.setAuthenticated(true); // must use super, as we override
	}

	public static AccountAuthenticationToken unauthenticated(String principal, String credentials) {
		return new AccountAuthenticationToken(principal, credentials);
	}

	public static AccountAuthenticationToken authenticated(String principal, String credentials,
                                                           Collection<? extends GrantedAuthority> authorities) {
		return new AccountAuthenticationToken(principal, credentials, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.password;
	}

	@Override
	public Object getPrincipal() {
		return this.username;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.password = null;
	}

}
