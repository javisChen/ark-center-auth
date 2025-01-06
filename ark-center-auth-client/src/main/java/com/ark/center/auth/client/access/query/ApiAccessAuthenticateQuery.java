package com.ark.center.auth.client.access.query;

import lombok.Data;

@Data
public class ApiAccessAuthenticateQuery {

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
