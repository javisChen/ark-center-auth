package com.ark.center.auth.infra.authentication.common;

public interface Uris {

    /**
     * Api校验
     */
    String ACCESS_API = "/v1/access/api";


    /**
     * 登录
     */
    String LOGIN = "/v1/login/*";

    /**
     * 登出
     */
    String LOGOUT = "/v1/logout";

    /**
     * 发送手机验证码
     */
    String SMS_CODE = "/v1/code/sms";
}
