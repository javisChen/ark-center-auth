package com.ark.center.auth.infra.authentication.login.account;

import cn.hutool.core.lang.Assert;
import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserService;
import com.ark.center.auth.infra.authentication.login.AbstractLoginAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.component.security.base.user.LoginUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
public class AccountLoginAuthenticationProvider extends AbstractLoginAuthenticationProvider<AccountAuthenticationToken> {

    private final UserService userGateway;
    private final UserConverter userConverter;
    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AccountLoginAuthenticationProvider(UserTokenGenerator userTokenGenerator,
                                              UserService userGateway, UserConverter userConverter) {
        super(userTokenGenerator);
        this.userGateway = userGateway;
        this.userConverter = userConverter;
    }

    @Override
    protected void preCheckAuthentication(AccountAuthenticationToken authentication) throws AuthenticationException {
        Assert.notBlank(authentication.getUsername(), () -> new BadCredentialsException("用户名或密码错误"));
        Assert.notBlank(authentication.getPassword(), () -> new BadCredentialsException("用户名或密码错误"));
    }

    @Override
    protected void additionalAuthenticationChecks(LoginUser user, AccountAuthenticationToken authenticationToken) {
        String presentedPassword = authenticationToken.getCredentials().toString();
        if (!this.passwordEncoder.matches(presentedPassword, user.getPassword())) {
            log.warn("Password does not match stored value");
            throw new BadCredentialsException("用户名或密码错误");
        }
    }

    @Override
    protected UserDetails retrieveUser(AccountAuthenticationToken authentication) throws AuthenticationException {
        AuthUser authUser = userGateway.retrieveUserByUsername(authentication.getUsername());
        Assert.notNull(authUser, () -> new UserNotFoundException("用户名或密码错误"));
        return userConverter.toLoginUser(authUser);
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

}