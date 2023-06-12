package com.ark.center.iam.client.access.request;

import lombok.Data;

@Data
public class ApiAccessRequest {

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