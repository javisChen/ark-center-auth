package com.ark.center.auth.infra.authentication;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;

public class LoginAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, LoginAuthenticationDetails> {

	@Override
	public LoginAuthenticationDetails buildDetails(HttpServletRequest context) {
		return new LoginAuthenticationDetails(context);
	}

}
