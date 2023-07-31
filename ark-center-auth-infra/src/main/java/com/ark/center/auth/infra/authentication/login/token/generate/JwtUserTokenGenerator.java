package com.ark.center.auth.infra.authentication.login.token.generate;


import com.ark.center.auth.infra.authentication.SecurityConstants;
import com.ark.center.auth.infra.authentication.login.LoginUser;
import com.ark.center.auth.infra.authentication.login.token.UserToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
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
        JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
        Instant expiresAt = issuedAt.plus(SecurityConstants.TOKEN_EXPIRES_SECONDS, ChronoUnit.SECONDS);
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
        claimsBuilder
                .claim("userCode", loginUser.getUserCode())
                .claim("userId", loginUser.getUserId())
                .claim("userName", loginUser.getUsername())
                .claim("isSuperAdmin", loginUser.getIsSuperAdmin())
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
