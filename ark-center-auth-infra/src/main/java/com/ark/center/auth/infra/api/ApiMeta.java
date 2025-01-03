package com.ark.center.auth.infra.api;

import com.ark.center.iam.client.contants.ApiAuthType;
import lombok.Data;

@Data
public class ApiMeta {
    /**
     * API名称
     */
    private String name;

    /**
     * 接口URI
     * 例如：/api/v1/users/{id}
     */
    private String uri;

    /**
     * HTTP请求方法
     * 例如：GET, POST, PUT, DELETE
     */
    private String method;

    /**
     * 认证类型
     * @see ApiAuthType
     * 1-无需认证授权
     * 2-需要认证
     * 3-需要授权
     */
    private ApiAuthType authType;

    /**
     * API状态
     * 1-已启用
     * 2-已禁用
     */
    private Integer status;

    /**
     * 是否包含路径参数
     * true-包含（如/users/{id}）
     * false-不包含（如/users/list）
     */
    private Boolean hasPathVariable;

    /**
     * 检查是否只需要认证
     */
    public boolean authenticationRequired() {
        return authType.equals(ApiAuthType.AUTHENTICATION_REQUIRED);
    }

    /**
     * 检查是否需要授权
     */
    public boolean authorizationRequired() {
        return authType.equals(ApiAuthType.AUTHORIZATION_REQUIRED);
    }

    /**
     * 检查是否无需认证和授权
     */
    public boolean noAuthRequired() {
        return authType.equals(ApiAuthType.ANONYMOUS);
    }
}
