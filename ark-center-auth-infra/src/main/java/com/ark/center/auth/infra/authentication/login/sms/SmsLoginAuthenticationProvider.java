package com.ark.center.auth.infra.authentication.login.sms;

import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.login.AbstractLoginAuthenticationProvider;
import com.ark.center.auth.infra.cache.AuthCacheKey;
import com.ark.component.cache.CacheService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class SmsLoginAuthenticationProvider extends AbstractLoginAuthenticationProvider {

    private final UserGateway userGateway;

    private final CacheService cacheService;

    public SmsLoginAuthenticationProvider(UserGateway userGateway, CacheService cacheService) {
        this.userGateway = userGateway;
        this.cacheService = cacheService;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        String requestCode = (String) authentication.getCredentials();
        String codeCacheKey = String.format(AuthCacheKey.CACHE_KEY_USER_MOBILE_LOGIN_CODE, authentication.getPrincipal());
        String cacheCode = cacheService.get(codeCacheKey, String.class);
        if (StringUtils.isBlank(cacheCode)) {
            throw new BadCredentialsException("验证码已过期，请重新获取");
        }
        if (!cacheCode.equals(requestCode)) {
            throw new BadCredentialsException("验证码错误");
        }
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        return userGateway.retrieveUserByMobile(username);
    }

}