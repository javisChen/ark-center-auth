package com.ark.center.auth.infra.authentication.token.generate;

import com.ark.center.auth.infra.authentication.LoginAuthenticationDetails;
import com.ark.center.auth.infra.authentication.token.TokenMetadata;
import com.ark.component.security.base.authentication.AuthUser;

public interface TokenGenerator {
    /**
     * 根据元数据生成token
     */
    String generateToken(TokenMetadata metadata, AuthUser authUser, LoginAuthenticationDetails details);
    
    /**
     * 生成刷新token
     */
    String generateRefreshToken();
}
