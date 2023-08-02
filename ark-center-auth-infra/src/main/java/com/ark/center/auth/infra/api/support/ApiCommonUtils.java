package com.ark.center.auth.infra.api.support;

public class ApiCommonUtils {

    public static String createKey(String url, String method) {
        return url + ":" + method;
    }
}
