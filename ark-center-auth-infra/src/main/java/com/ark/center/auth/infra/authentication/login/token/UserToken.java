package com.ark.center.auth.infra.authentication.login.token;

import org.springframework.lang.Nullable;

import java.time.Instant;

/**
 * 用户Token
 */
public interface UserToken {

    /**
     * Token
     *
     * @return 返回Token值
     */
    String getTokenValue();

    /**
     * 签发日期
     *
     * @return 返回Token签发日期
     */
    @Nullable
    default Instant getIssuedAt() {
        return null;
    }

    /**
     * 有效期
     *
     * @return 返回Token有效期
     */
    @Nullable
    default Instant getExpiresAt() {
        return null;
    }
}
