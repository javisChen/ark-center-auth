package com.ark.center.auth.infra.authentication.token.generator;

import com.ark.center.auth.infra.authentication.token.JwtUserToken;
import com.ark.center.auth.infra.authentication.token.UserToken;
import com.ark.component.security.base.user.LoginUser;
import com.ark.component.security.core.common.SecurityConstants;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import lombok.RequiredArgsConstructor;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;

/**
 * JWT Token生成器实现
 * 负责生成包含用户信息的JWT令牌和刷新令牌
 */
@RequiredArgsConstructor
public class JwtUserTokenGenerator implements UserTokenGenerator {

    private final JwtEncoder jwtEncoder;

    private final SignatureAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;

    /**
     * 生成用户Token
     * 包含JWT访问令牌和刷新令牌
     *
     * @param loginUser 登录用户信息
     * @return 包含访问令牌和刷新令牌的UserToken对象
     */
    @Override
    public UserToken generate(LoginUser loginUser) {
        JwtClaimsSet claims = buildClaims(loginUser);
        JwsHeader jwsHeader = JwsHeader
                .with(jwsAlgorithm)
                .build();
        JwtEncoderParameters parameters = JwtEncoderParameters.from(jwsHeader, claims);
        Jwt jwt = jwtEncoder.encode(parameters);
        
        String refreshToken = generateRefreshToken();
        
        return new JwtUserToken(
            jwt.getTokenValue(),
            jwt.getHeaders(),
            jwt.getClaims(),
            refreshToken,
            jwt.getIssuedAt(),
            jwt.getExpiresAt()
        );
    }
    
    /**
     * 构建JWT载荷信息
     * 包含用户基本信息、权限信息和令牌有效期等
     *
     * @param loginUser 登录用户信息
     * @return JWT Claims集合
     */
    private JwtClaimsSet buildClaims(LoginUser loginUser) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(SecurityConstants.TOKEN_EXPIRES_SECONDS, ChronoUnit.SECONDS);

        return JwtClaimsSet.builder()
            // 基础信息
            .issuer("auth")                    // 签发者
            .issuedAt(issuedAt)               // 签发时间
            .expiresAt(expiresAt)             // 过期时间
            .subject(loginUser.getUsername())  // 主题(用户名)
            .audience(Collections.emptyList()) // 接收方
            // 用户信息
            .claim(LoginUser.JWT_CLAIM_USER_CODE, loginUser.getUserCode())           // 用户编码
            .claim(LoginUser.JWT_CLAIM_USER_ID, loginUser.getUserId())               // 用户ID
            .claim(LoginUser.JWT_CLAIM_USERNAME, loginUser.getUsername())            // 用户名
            .claim(LoginUser.JWT_CLAIM_USER_IS_SUPER_ADMIN, loginUser.getIsSuperAdmin()) // 是否超级管理员
            // 权限信息
            .claim("authorities", getAuthorities(loginUser))  // 用户权限列表
            .build();
    }
    
    /**
     * 生成刷新令牌
     * 用于在访问令牌过期时获取新的访问令牌
     *
     * @return 刷新令牌字符串
     */
    private String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * 提取用户权限列表
     * 将GrantedAuthority转换为字符串列表
     *
     * @param loginUser 登录用户信息
     * @return 权限字符串列表
     */
    private List<String> getAuthorities(LoginUser loginUser) {
        return loginUser.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());
    }
}
