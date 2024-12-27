package com.ark.center.auth.infra.authentication.login.account;

import cn.hutool.core.util.StrUtil;
import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.login.AbstractLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.component.security.base.user.LoginUser;
import com.ark.component.security.core.token.issuer.TokenIssuer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 账号密码登录认证提供者
 * 负责处理账号密码方式的登录认证
 */
@Slf4j
@Component
public class AccountLoginAuthenticationProvider extends AbstractLoginAuthenticationProvider<AccountAuthenticationToken> {

    private static final String INVALID_CREDENTIALS_MSG = "用户名或密码错误";
    private static final String ACCOUNT_DISABLED_MSG = "账号已被禁用";
    private static final String ACCOUNT_LOCKED_MSG = "账号已被锁定";
    private static final String ACCOUNT_EXPIRED_MSG = "账号已过期";
    private static final String SERVICE_ERROR_MSG = "系统繁忙，请稍后重试";

    private final UserGateway userGateway;
    private final UserConverter userConverter;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public AccountLoginAuthenticationProvider(TokenIssuer tokenIssuer,
                                              UserGateway userGateway,
                                              UserConverter userConverter,
                                              PasswordEncoder passwordEncoder,
                                              UserDetailsService userDetailsService) {
        super(tokenIssuer);
        this.userGateway = userGateway;
        this.userConverter = userConverter;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void preCheckAuthentication(AccountAuthenticationToken authentication) throws AuthenticationException {
        // 预检查用户名密码是否为空
        if (StrUtil.hasBlank(authentication.getUsername(), authentication.getPassword())) {
            throw new BadCredentialsException(INVALID_CREDENTIALS_MSG);
        }
    }

    @Override
    protected void additionalAuthenticationChecks(LoginUser user, AccountAuthenticationToken authentication) {
        checkAccountStatus(user);
        verifyPassword(user, authentication);
    }

    /**
     * 检查账号状态
     */
    private void checkAccountStatus(LoginUser user) {
        if (!user.isEnabled()) {
            throw new DisabledException(ACCOUNT_DISABLED_MSG);
        }
        if (!user.isAccountNonLocked()) {
            throw new LockedException(ACCOUNT_LOCKED_MSG);
        }
        if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException(ACCOUNT_EXPIRED_MSG);
        }
    }

    /**
     * 验证密码
     */
    private void verifyPassword(LoginUser user, AccountAuthenticationToken authentication) {
        String presentedPassword = authentication.getCredentials().toString();
        if (!passwordEncoder.matches(presentedPassword, user.getPassword())) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate since password does not match for user: {}", 
                    authentication.getUsername());
            }
            throw new BadCredentialsException(INVALID_CREDENTIALS_MSG);
        }
    }

    @Override
    protected UserDetails retrieveUser(AccountAuthenticationToken authentication) throws AuthenticationException {
        try {
            AuthUser authUser = userGateway.retrieveUserByUsername(authentication.getUsername());
            if (authUser == null) {
                log.warn("User not found: {}", authentication.getUsername());
                throw new UserNotFoundException(INVALID_CREDENTIALS_MSG);
            }
            return userConverter.toLoginUser(authUser);
        } catch (UserNotFoundException e) {
            throw e;
        } catch (Exception ex) {
            log.error("Failed to authenticate user: {}", authentication.getUsername(), ex);
            throw new AuthenticationServiceException(SERVICE_ERROR_MSG);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AccountAuthenticationToken.class.isAssignableFrom(authentication);
    }
}