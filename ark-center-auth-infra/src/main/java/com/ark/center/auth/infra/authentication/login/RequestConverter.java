package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.io.IoUtil;
import cn.hutool.core.util.ClassUtil;
import com.alibaba.fastjson2.JSON;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 认证请求转换器抽象类
 * 提供HTTP请求体到指定类型的转换功能
 *
 * @param <T> 目标转换类型
 * @author JC
 */
@Slf4j
public abstract class RequestConverter<T extends BaseLoginAuthenticateRequest> {

	/**
	 * 目标转换类型的Class对象
	 */
	private final Class<T> clazz;

	/**
	 * 构造方法
	 * 通过反射获取泛型的实际类型
	 */
	@SuppressWarnings("unchecked")
	public RequestConverter() {
		this.clazz = (Class<T>) ClassUtil.getTypeArgument(getClass());
		log.debug("Initializing RequestConverter for type: {}", this.clazz.getSimpleName());
	}

	/**
	 * 读取并转换请求体到目标类型
	 *
	 * @param request HTTP请求对象
	 * @return 转换后的目标类型对象
	 * @throws RuntimeException 当读取或转换失败时抛出
	 */
	public T readFromRequest(HttpServletRequest request) {
		String reqBody;
		try {
			reqBody = IoUtil.read(request.getInputStream()).toString(StandardCharsets.UTF_8);
			if (log.isDebugEnabled()) {
				log.debug("Request body content: {}", reqBody);				
			}
		} catch (IOException e) {
			log.error("Failed to read request input stream: {}", e.getMessage(), e);
			throw new RuntimeException("Failed to read request body", e);
		}

		try {
			T result = JSON.to(this.clazz, reqBody);
			log.debug("Successfully converted request body to type: {}", this.clazz.getSimpleName());
			return result;
		} catch (Exception e) {
			log.error("Failed to convert request body to type {}: {}", this.clazz.getSimpleName(), e.getMessage(), e);
			throw new RuntimeException("Failed to parse request body", e);
		}
	}
}
