package com.ark.center.auth.infra.api;

/**
 * API请求的组合键，用于标识唯一的API请求
 */
public record ApiCacheKey(String uri, String method) {

    private static final String DELIMITER = ":";

    public static String generateRedisKey(String uri, String method) {
        return uri + DELIMITER + method;
    }

    public static String generateRedisKey(ApiMeta api) {
        return generateRedisKey(api.getUri(), api.getMethod());
    }

    @Override
    public String toString() {
        return String.format("ApiKey[uri=%s, method=%s]", uri, method);
    }
} 