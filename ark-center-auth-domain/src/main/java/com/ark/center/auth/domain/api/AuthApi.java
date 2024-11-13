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

    public boolean authenticationRequired() {
        return authType.equals(ApiAuthTypeEnums.AUTHENTICATION_REQUIRED.getValue());
    }

    public boolean authorizationRequired() {
        return authType.equals(ApiAuthTypeEnums.AUTHORIZATION_REQUIRED.getValue());
    }
    public boolean noAuthRequired() {
        return authType.equals(ApiAuthTypeEnums.NO_AUTH_REQUIRED.getValue());
    }

}
