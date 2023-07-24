
package com.ark.center.auth.infra;

import com.alibaba.fastjson2.JSON;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.entity.ContentType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class DefaultAuthenticationEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {


	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException {

		setResponse(response);

		ServerResponse responseBody = createBody();
		
		doWrite(response, responseBody);
	}

	private void setResponse(HttpServletResponse response) {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
		response.setContentType(ContentType.APPLICATION_JSON.getMimeType());
	}

	private void doWrite(HttpServletResponse response, ServerResponse serverResponse) throws IOException {
		response.getWriter().write(JSON.toJSONString(serverResponse));
	}

	private ServerResponse createBody() {
		return SingleResponse.error("auth", "UNAUTHORIZED", "访问该资源需要先进行身份验证");
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		response.getWriter().write("access denied");
	}
}
