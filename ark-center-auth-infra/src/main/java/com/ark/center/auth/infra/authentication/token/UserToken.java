package com.ark.center.auth.infra.authentication.token;

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
    String getToken();

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

    /**
     * 刷新令牌
     *
     * @return 返回刷新令牌
     */
    String getRefreshToken();

    /**
     * 令牌过期时间
     *
     * @return 返回令牌过期时间
     */
    Long getExpiresIn();

    /**
     * 令牌类型
     *
     * @return 返回令牌类型
     */
    String getTokenType();
}
