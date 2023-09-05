package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.util.ClassUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

@Slf4j
public abstract class LoginAuthenticationConverter<T> extends RequestConverter<T> implements AuthenticationConverter, InitializingBean {

	private Class<T> clazz;


	@Override
	@SuppressWarnings("unchecked")
	public void afterPropertiesSet() {
		this.clazz = (Class<T>) ClassUtil.getTypeArgument(getClass());;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		T authenticateRequest = getRequest(request);
		return internalConvert(request, authenticateRequest);
	}

	@NotNull
	private T getRequest(HttpServletRequest request) {
		T authenticateRequest = null;
		try {
			authenticateRequest = readFromRequest(request);
		} catch (Exception e) {
			log.error("读取认证参数失败", e);
			throw new AuthenticationServiceException("认证参数不合法");
		}
		if (authenticateRequest == null) {
			throw new AuthenticationServiceException("认证参数不合法");
		}
		return authenticateRequest;
	}

	protected abstract Authentication internalConvert(HttpServletRequest request, T authenticateRequest);

//	private T readFromRequest(HttpServletRequest request) {
//		T request;
//		try {
//			String reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
//			request = readFromRequest(request)
//		} catch (Exception e) {
//			log.error("读取认证参数失败", e);
//			throw new AuthenticationServiceException("认证参数不合法");
//		}
//		if (request == null) {
//			throw new AuthenticationServiceException("认证参数不合法");
//		}
//		return request;
//	}

	protected abstract boolean supports(LoginMode loginMode);


}
