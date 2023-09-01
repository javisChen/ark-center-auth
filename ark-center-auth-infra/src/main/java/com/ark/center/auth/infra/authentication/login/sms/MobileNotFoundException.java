package com.ark.center.auth.infra.authentication.login.sms;

import org.springframework.security.core.AuthenticationException;

public class MobileNotFoundException extends AuthenticationException {

	public MobileNotFoundException(String msg) {
		super(msg);
	}

	public MobileNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
