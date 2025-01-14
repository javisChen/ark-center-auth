package com.ark.center.auth.infra.authentication.api;

import cn.hutool.core.io.IoUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.nio.charset.StandardCharsets;

@Slf4j
public final class ApiAccessAuthenticationConverter implements AuthenticationConverter {

	private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

	@Override
	public Authentication convert(HttpServletRequest request) {
		ApiAccessAuthenticateQuery authenticateRequest = readFromRequest(request);
		return ApiAccessAuthenticationToken
				.unauthenticated(authenticateRequest, authenticateRequest.getAccessToken());
	}

	private ApiAccessAuthenticateQuery readFromRequest(HttpServletRequest request) {
		String token = bearerTokenResolver.resolve(request);
		ApiAccessAuthenticateQuery authenticateRequest;
		try {
			String reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
			authenticateRequest = JSON.to(ApiAccessAuthenticateQuery.class, reqBody);
		} catch (Exception e) {
			log.error("读取API认证参数失败", e);
			throw new AuthenticationServiceException("API认证参数不合法");
		}
		if (authenticateRequest == null) {
			throw new AuthenticationServiceException("API认证参数不合法");
		}
		authenticateRequest.setAccessToken(token);
		return authenticateRequest;
	}

}
