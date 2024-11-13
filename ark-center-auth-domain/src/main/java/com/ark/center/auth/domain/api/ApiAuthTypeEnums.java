package com.ark.center.auth.domain.api;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ApiAuthTypeEnums {

    NO_AUTH_REQUIRED(1, "无需认证授权"),
    AUTHENTICATION_REQUIRED(2, "只需认证无需授权"),
    AUTHORIZATION_REQUIRED(3, "需要认证和授权");

    private final int value;
    private final String desc;

}