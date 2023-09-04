package com.ark.center.auth.infra.authentication.code;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ClassUtil;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.infra.authentication.login.LoginMode;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.nio.charset.StandardCharsets;

@Slf4j
public abstract class SendSmsCodeConverter<T> implements AuthenticationConverter, InitializingBean {

	private Class<T> clazz;


	@Override
	@SuppressWarnings("unchecked")
	public void afterPropertiesSet() {
		this.clazz = (Class<T>) ClassUtil.getTypeArgument(getClass());;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		T authenticateRequest = readFromRequest(request);
		return internalConvert(request, authenticateRequest);
	}

	protected abstract Authentication internalConvert(HttpServletRequest request, T authenticateRequest);

	private T readFromRequest(HttpServletRequest request) {
		T authenticateRequest;
		try {
			String reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
			authenticateRequest = JSON.to(this.clazz, reqBody);
		} catch (Exception e) {
			log.error("读取认证参数失败", e);
			throw new AuthenticationServiceException("认证参数不合法");
		}
		if (authenticateRequest == null) {
			throw new AuthenticationServiceException("认证参数不合法");
		}
		return authenticateRequest;
	}

	protected abstract boolean supports(LoginMode loginMode);


}
