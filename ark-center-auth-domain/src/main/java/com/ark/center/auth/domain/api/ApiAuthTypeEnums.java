package com.ark.center.auth.domain.api;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ApiAuthTypeEnums {

    NO_NEED_AUTH(1, "无需认证授权"),
    NEED_AUTHENTICATION(2, "只需认证无需授权"),
    NEED_AUTHORIZATION(3, "需要认证和授权");

    private final int value;
    private final String desc;

}