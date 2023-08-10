package com.ark.center.auth.infra.authentication.api;

import com.ark.center.auth.infra.authentication.DefaultAuthenticationHandler;
import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.component.dto.ServerResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.core.Authentication;

import java.io.IOException;

@Slf4j
public class ApiAccessAuthenticationHandler extends DefaultAuthenticationHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        writeSuccess(response, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        writeSuccess(response, authentication);
    }

    private void writeSuccess(HttpServletResponse response, Authentication authentication) throws IOException {
        ServerResponse serverResponse = ServerResponse.ok();
        ResponseUtils.write(serverResponse, response, HttpStatus.SC_OK);
    }

}
