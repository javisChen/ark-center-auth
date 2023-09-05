package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ClassUtil;
import com.alibaba.fastjson2.JSON;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public abstract class RequestConverter<T> {

	private Class<T> clazz;

	@SuppressWarnings("unchecked")
	public RequestConverter() {
		this.clazz = (Class<T>) ClassUtil.getTypeArgument(getClass());;
	}

	public T readFromRequest(HttpServletRequest request) {
		String reqBody;
		try {
			reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
		} catch (IOException e) {
			log.error("Read input stream error", e);
			throw new RuntimeException(e);
		}
		return JSON.to(this.clazz, reqBody);
	}


}
