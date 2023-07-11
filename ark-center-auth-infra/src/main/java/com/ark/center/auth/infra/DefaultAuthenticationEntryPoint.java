
package com.ark.center.auth.infra;

import com.alibaba.fastjson2.JSON;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.entity.ContentType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class DefaultAuthenticationEntryPoint implements AuthenticationEntryPoint {


	/**
	 * Always returns a 403 error code to the client.
	 */
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException arg2)
			throws IOException {
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
		response.setContentType(ContentType.APPLICATION_JSON.getMimeType());
		ServerResponse serverResponse = SingleResponse.error("auth", "403", "权限不足，拒绝访问");
		response.getWriter().write(JSON.toJSONString(serverResponse));
	}

}
