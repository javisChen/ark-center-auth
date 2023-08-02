package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.io.IoUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.infra.authentication.SecurityConstants;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.nio.charset.StandardCharsets;

@Slf4j
public final class LoginAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		LoginAuthenticateRequest authenticateRequest = readFromRequest(request);
		return UsernamePasswordAuthenticationToken
				.unauthenticated(authenticateRequest.getUsername(), authenticateRequest.getPassword());
	}

	private LoginAuthenticateRequest readFromRequest(HttpServletRequest request) {
		LoginAuthenticateRequest authenticateRequest;
		try {
			String reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
			authenticateRequest = JSON.to(LoginAuthenticateRequest.class, reqBody);
		} catch (Exception e) {
			log.error("读取认证参数失败", e);
			throw new AuthenticationServiceException("认证参数不合法");
		}
		if (authenticateRequest == null) {
			throw new AuthenticationServiceException("认证参数不合法");
		}
		authenticateRequest.setPassword(DigestUtil.md5Hex(authenticateRequest.getPassword()) + SecurityConstants.PASSWORD_SALT);
		return authenticateRequest;
	}

}
