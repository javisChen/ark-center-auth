package com.ark.center.auth.infra.authentication.login.sms;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.util.Collection;

public class SmsAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String mobile;

	private String code;

	public SmsAuthenticationToken(String mobile, String code) {
		super(null);
		this.mobile = mobile;
		this.code = code;
		setAuthenticated(false);
	}

	public SmsAuthenticationToken(String mobile, String code,
								  Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.mobile = mobile;
		this.code = code;
		super.setAuthenticated(true); // must use super, as we override
	}

	public static SmsAuthenticationToken unauthenticated(String principal, String credentials) {
		return new SmsAuthenticationToken(principal, credentials);
	}

	public static SmsAuthenticationToken authenticated(String principal, String credentials,
													   Collection<? extends GrantedAuthority> authorities) {
		return new SmsAuthenticationToken(principal, credentials, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.code;
	}

	@Override
	public Object getPrincipal() {
		return this.mobile;
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
		this.code = null;
	}

}
