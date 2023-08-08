package com.ark.center.auth.infra.authentication.api;

import cn.hutool.core.io.IoUtil;
import com.alibaba.fastjson2.JSON;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.nio.charset.StandardCharsets;

@Slf4j
public final class ApiAccessAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		ApiAccessAuthenticateRequest authenticateRequest = readFromRequest(request);
		return ApiAccessAuthenticationToken
				.unauthenticated(authenticateRequest, null);
	}

	private ApiAccessAuthenticateRequest readFromRequest(HttpServletRequest request) {
		ApiAccessAuthenticateRequest authenticateRequest;
		try {
			String reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
			authenticateRequest = JSON.to(ApiAccessAuthenticateRequest.class, reqBody);
		} catch (Exception e) {
			log.error("读取认证参数失败", e);
			throw new AuthenticationServiceException("认证参数不合法");
		}
		if (authenticateRequest == null) {
			throw new AuthenticationServiceException("认证参数不合法");
		}
		return authenticateRequest;
	}

}
