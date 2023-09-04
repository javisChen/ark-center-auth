package com.ark.center.auth.infra.authentication.login;

import java.util.Arrays;

public enum LoginMode {

    ACCOUNT("ACCOUNT", "账号登录"),
    MOBILE("MOBILE", "手机登录");

    ;
    private final String code;
    private final String name;

    LoginMode(String code, String name) {
        this.code = code;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public String getCode() {
        return code;
    }

    public static LoginMode byCode(String code) {
        return Arrays.stream(values())
                .filter(loginMode -> loginMode.code.equals(code.toUpperCase()))
                .findFirst()
                .orElse(null);
    }
}
