package com.ark.center.auth.infra.authentication.api;

import lombok.Data;

@Data
public class ApiAccessAuthenticateRequest {

    /**
     * token
     */
    private String accessToken;

    /**
     * 资源uri
     */
    private String requestUri;

    /**
     * http方法
     */
    private String httpMethod;

    /**
     * 应用编码
     */
    private String applicationCode;
}
