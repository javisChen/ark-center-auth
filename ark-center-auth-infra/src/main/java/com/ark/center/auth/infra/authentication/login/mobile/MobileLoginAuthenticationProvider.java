package com.ark.center.auth.infra.authentication.login.mobile;

import cn.hutool.core.lang.Assert;
import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.login.AbstractLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.center.auth.infra.cache.AuthCacheKey;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.component.cache.CacheService;
import com.ark.component.security.base.user.LoginUser;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class MobileLoginAuthenticationProvider extends AbstractLoginAuthenticationProvider<MobileAuthenticationToken> {

    private final UserGateway userGateway;

    private final CacheService cacheService;

    private final UserConverter userConverter;

    public MobileLoginAuthenticationProvider(UserTokenGenerator userTokenGenerator,
                                             UserGateway userGateway,
                                             CacheService cacheService,
                                             UserConverter userConverter) {
        super(userTokenGenerator);
        this.userGateway = userGateway;
        this.cacheService = cacheService;
        this.userConverter = userConverter;
    }


    @Override
    protected void preCheckAuthentication(MobileAuthenticationToken authentication) throws AuthenticationException {
        Assert.notBlank(authentication.getMobile(), () -> new BadCredentialsException("手机号不能为空"));
        Assert.notBlank(authentication.getCode(), () -> new BadCredentialsException("无效的验证码"));
    }

    @Override
    protected void additionalAuthenticationChecks(LoginUser user, MobileAuthenticationToken authenticationToken) {
        String requestCode = authenticationToken.getCode();
        String mobile = authenticationToken.getMobile();
        String codeCacheKey = String.format(AuthCacheKey.CACHE_KEY_USER_MOBILE_LOGIN_CODE, mobile);

        // 缓存的登录验证码
        String cacheCode = cacheService.get(codeCacheKey, String.class);
        Assert.equals(requestCode, cacheCode, () -> new BadCredentialsException("无效的验证码"));
    }

    @Override
    protected UserDetails retrieveUser(MobileAuthenticationToken authentication) throws AuthenticationException {
        AuthUser authUser = userGateway.retrieveUserByMobile(authentication.getMobile());
        // todo 这里可以调整成没有注册就自动注册一个
        Assert.notNull(authUser, () -> new UserNotFoundException("该手机没有注册用户"));
        return userConverter.toLoginUser(authUser);
    }

    @Override
    protected void postHandle(UserDetails user, MobileAuthenticationToken authenticationToken) {
        String mobile = authenticationToken.getMobile();
        String codeCacheKey = String.format(AuthCacheKey.CACHE_KEY_USER_MOBILE_LOGIN_CODE, mobile);
        cacheService.remove(codeCacheKey);
    }
}