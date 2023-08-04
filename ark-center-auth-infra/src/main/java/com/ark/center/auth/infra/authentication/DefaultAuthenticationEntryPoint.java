
package com.ark.center.auth.infra.authentication;

import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

@Slf4j
public class DefaultAuthenticationEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {


	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException {

		ServerResponse responseBody = SingleResponse.error("auth", "UNAUTHORIZED", "访问该资源需要先进行身份验证");
		ResponseUtils.write(responseBody, response, HttpStatus.SC_UNAUTHORIZED);
		
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
		ServerResponse responseBody = SingleResponse.error("auth", "UNAUTHORIZED", "access denied");
		ResponseUtils.write(responseBody, response, HttpStatus.SC_FORBIDDEN);

	}
}
