package com.ark.center.auth.infra.authentication.token.generator;

import com.ark.center.auth.infra.authentication.token.JwtUserToken;
import com.ark.center.auth.infra.authentication.token.UserToken;
import com.ark.component.security.base.user.LoginUser;
import com.ark.component.security.core.common.SecurityConstants;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

public class JwtUserTokenGenerator implements UserTokenGenerator {
    private final JwtEncoder jwtEncoder;

    public JwtUserTokenGenerator(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * 生成JWT令牌
     * withSubject  ：主题
     * withJWTId    ：JWT唯一ID
     * withExpiresAt：JWT的过期时间
     * withNotBefore：JWT生效时间
     * withIssuedAt ：JWT签发时间
     *
     * @param loginUser 用户上下文
     * @return Token
     */
    @Override
    public UserToken generate(LoginUser loginUser) {
        Instant issuedAt = Instant.now();
        JwsAlgorithm jwsAlgorithm = MacAlgorithm.HS256;
        Instant expiresAt = issuedAt.plus(SecurityConstants.TOKEN_EXPIRES_SECONDS, ChronoUnit.SECONDS);
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
        claimsBuilder
                .claim(LoginUser.JWT_CLAIM_USER_CODE, loginUser.getUserCode())
                .claim(LoginUser.JWT_CLAIM_USER_ID, loginUser.getUserId())
                .claim(LoginUser.JWT_CLAIM_USERNAME, loginUser.getUsername())
                .claim(LoginUser.JWT_CLAIM_USER_IS_SUPER_ADMIN, loginUser.getIsSuperAdmin())
                .issuer("auth")
                .subject(loginUser.getUsername())
                .audience(Collections.emptyList())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt);
        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);
        JwsHeader jwsHeader = jwsHeaderBuilder.build();
        JwtClaimsSet claims = claimsBuilder.build();
        Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
        return new JwtUserToken(jwt.getTokenValue(), jwt.getHeaders(), jwt.getClaims());
    }

}
