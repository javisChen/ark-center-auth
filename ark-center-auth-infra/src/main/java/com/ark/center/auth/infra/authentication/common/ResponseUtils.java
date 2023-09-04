package com.ark.center.auth.infra.authentication.common;

import com.alibaba.fastjson2.JSON;
import com.ark.component.dto.ServerResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.entity.ContentType;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ResponseUtils {

    public static void write(ServerResponse serverResponse, HttpServletResponse response, int status) throws IOException {
        byte[] body = JSON.toJSONBytes(serverResponse);
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
        response.setContentType(ContentType.APPLICATION_JSON.getMimeType());
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }

    public static void writeOk(ServerResponse serverResponse, HttpServletResponse response) throws IOException {
        write(serverResponse, response, HttpStatus.OK.value());
    }
}
