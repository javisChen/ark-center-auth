package com.ark.center.auth.infra.authentication.token;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.time.Instant;

public abstract class AbstractUserToken implements UserToken {

    private final String tokenValue;

    private final Instant issuedAt;

    private final Instant expiresAt;

    protected AbstractUserToken(String tokenValue) {
        this(tokenValue, null, null);
    }

    protected AbstractUserToken(String tokenValue, @Nullable Instant issuedAt, @Nullable Instant expiresAt) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        if (issuedAt != null && expiresAt != null) {
            Assert.isTrue(expiresAt.isAfter(issuedAt), "expiresAt must be after issuedAt");
        }
        this.tokenValue = tokenValue;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getToken() {
        return this.tokenValue;
    }

    @Nullable
    public Instant getIssuedAt() {
        return this.issuedAt;
    }

    @Nullable
    public Instant getExpiresAt() {
        return this.expiresAt;
    }



}
