package com.ark.center.auth.infra.api;

/**
 * API请求的组合键，用于标识唯一的API请求
 */
public record ApiCacheKey(String uri, String method) {
    @Override
    public String toString() {
        return String.format("ApiKey[uri=%s, method=%s]", uri, method);
    }
} 