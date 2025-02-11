package com.ark.center.auth.infra.authentication.context;

import com.ark.component.security.base.authentication.AuthUser;
import com.ark.component.security.base.authentication.Token;
import com.ark.component.security.base.token.JwtBody;
import lombok.Getter;

import java.util.List;
import java.util.stream.Stream;

/**
 * 用户认证缓存键枚举
 */
@Getter
public enum AuthenticatedCacheKeys {
    USER_ID(AuthUser.USER_ID),
    USER_CODE(AuthUser.USER_CODE),
    IS_SUPER_ADMIN("isSuperAdmin"),
    PASSWORD("password"),
    USERNAME(AuthUser.USERNAME),
    AUTHORITIES("authorities"),
    ACCOUNT_NON_EXPIRED("accountNonExpired"),
    ACCOUNT_NON_LOCKED("accountNonLocked"),
    CREDENTIALS_NON_EXPIRED("credentialsNonExpired"),
    ENABLED("enabled"),
    APP_CODE(Token.APP_CODE),
    APP_TYPE(Token.APP_TYPE);

    private final Object value;
    private final int index;

    private static final List<Object> KEYS = Stream.of(values())
            .map(field -> field.value)
            .toList();

    AuthenticatedCacheKeys(Object value) {
        this.value = value;
        this.index = ordinal();
    }

    public static List<Object> getKeys() {
        return KEYS;
    }
} 