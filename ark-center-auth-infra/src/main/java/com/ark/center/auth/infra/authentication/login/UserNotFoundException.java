package com.ark.center.auth.infra.authentication.login;

import org.springframework.security.core.AuthenticationException;

public class UserNotFoundException extends AuthenticationException {

	public UserNotFoundException(String msg) {
		super(msg);
	}

	public UserNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
