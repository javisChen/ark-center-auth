package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.util.ClassUtil;
import com.ark.center.auth.client.authentication.command.BaseLoginAuthenticateRequest;
import lombok.extern.slf4j.Slf4j;

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
	protected final Class<T> clazz;

	/**
	 * 构造方法
	 * 通过反射获取泛型的实际类型
	 */
	@SuppressWarnings("unchecked")
	public RequestConverter() {
		this.clazz = (Class<T>) ClassUtil.getTypeArgument(getClass());
		log.debug("Initializing RequestConverter for type: {}", this.clazz.getSimpleName());
	}

}
