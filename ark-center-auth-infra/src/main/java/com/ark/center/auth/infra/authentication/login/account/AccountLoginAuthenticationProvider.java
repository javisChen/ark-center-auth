package com.ark.center.auth.infra.authentication.login.account;

import com.ark.center.auth.infra.authentication.LoginAuthenticationDetails;
import com.ark.center.auth.infra.authentication.login.provider.UserDetailsAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.authentication.login.userdetails.AuthenticationUserService;
import com.ark.center.auth.infra.authentication.token.issuer.TokenIssuer;
import com.ark.component.security.base.authentication.AuthUser;
import com.ark.component.security.base.password.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 账号密码登录认证提供者
 * 负责处理账号密码方式的登录认证
 */
@Slf4j
@Component
public class AccountLoginAuthenticationProvider extends UserDetailsAuthenticationProvider {

    private final AuthenticationUserService authenticationUserService;
    private final PasswordService passwordService;

    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";
    private volatile String userNotFoundEncodedPassword;

    public AccountLoginAuthenticationProvider(AuthenticationUserService authenticationUserService,
                                              TokenIssuer tokenIssuer,
                                              PasswordService passwordService) {
        super(tokenIssuer);
        this.authenticationUserService = authenticationUserService;
        this.passwordService = passwordService;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, Authentication authentication, LoginAuthenticationDetails details) throws AuthenticationException {
        String presentedPassword = authentication.getCredentials().toString();
        if (!this.passwordService.checkPassword(presentedPassword, userDetails.getPassword())) {
            if (log.isDebugEnabled()) {
                this.logger.debug("Failed to authenticate since password does not match stored value");
            }
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    }

    @Override
    protected AuthUser retrieveUser(String username, Authentication authentication) throws AuthenticationException {
        prepareTimingAttackProtection();
        try {
            AuthUser loadedUser = authenticationUserService.loadUserByUsername(username, authentication);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        } catch (UserNotFoundException ex) {
            mitigateAgainstTimingAttack(authentication);
            throw ex;
        } catch (InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AccountAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private void prepareTimingAttackProtection() {
        if (this.userNotFoundEncodedPassword == null) {
            this.userNotFoundEncodedPassword = this.passwordService.enhancePassword(USER_NOT_FOUND_PASSWORD);
        }
    }

    private void mitigateAgainstTimingAttack(Authentication authentication) {
        if (authentication.getCredentials() != null) {
            String presentedPassword = authentication.getCredentials().toString();
            this.passwordService.checkPassword(presentedPassword, this.userNotFoundEncodedPassword);
        }
    }
}