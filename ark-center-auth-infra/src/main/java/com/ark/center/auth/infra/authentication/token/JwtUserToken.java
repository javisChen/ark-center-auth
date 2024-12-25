package com.ark.center.auth.infra.authentication.token;

import lombok.Getter;
import java.time.Instant;
import java.util.Map;

/**
 * JWT令牌实现
 */
@Getter
public class JwtUserToken extends AbstractUserToken {

    private final Map<String, Object> headers;  // JWT headers
    private final Map<String, Object> claims;   // JWT payload claims
    private final String refreshToken;          // 刷新令牌
    private final Instant issuedAt;            // 签发时间
    private final Instant expiresAt;           // 过期时间
    private final Long expiresIn;              // 过期时间(秒)

    public JwtUserToken(String tokenValue, 
                       Map<String, Object> headers, 
                       Map<String, Object> claims,
                       String refreshToken,
                       Instant issuedAt,
                       Instant expiresAt) {
        super(tokenValue);
        this.headers = headers;
        this.claims = claims;
        this.refreshToken = refreshToken;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.expiresIn = calculateExpiresIn(expiresAt);
    }

    @Override
    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public Long getExpiresIn() {
        return expiresIn;
    }

    @Override
    public String getTokenType() {
        return "Bearer";
    }

    @Override
    public Instant getIssuedAt() {
        return issuedAt;
    }

    @Override
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /**
     * 计算令牌剩余有效期(秒)
     */
    private Long calculateExpiresIn(Instant expiresAt) {
        if (expiresAt == null) {
            return null;
        }
        return expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
    }
}
