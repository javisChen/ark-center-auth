package com.ark.center.auth.domain.api;

import lombok.Data;

@Data
public class AuthApi {

    private String name;
    private String uri;
    private String method;
    private Integer authType;
    private Integer status;
    private Boolean hasPathVariable;

    public boolean isNeedAuthentication() {
        return authType.equals(ApiAuthTypeEnums.NEED_AUTHENTICATION.getValue());
    }

    public boolean isNeedAuthorization() {
        return authType.equals(ApiAuthTypeEnums.NEED_AUTHORIZATION.getValue());
    }
    public boolean isNoNeedAuth() {
        return authType.equals(ApiAuthTypeEnums.NO_NEED_AUTH.getValue());
    }

}
