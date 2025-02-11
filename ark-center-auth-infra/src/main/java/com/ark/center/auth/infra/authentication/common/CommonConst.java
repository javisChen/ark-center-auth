package com.ark.center.auth.infra.authentication.common;

/**
 * 认证相关常量
 */
public interface CommonConst {

    /**
     * 登录
     */
    String URI_LOGIN = "/v1//login";

    /**
     * 登出
     */
    String URI_LOGOUT = "/v1/logout";


    String LOGIN_REQUEST_BODY_ATTR = "LOGIN_REQUEST_BODY";

    String BASE_LOGIN_REQUEST = "BASE_LOGIN_REQUEST";

    String APPLICATION_CONFIG = "APPLICATION_CONFIG";

}