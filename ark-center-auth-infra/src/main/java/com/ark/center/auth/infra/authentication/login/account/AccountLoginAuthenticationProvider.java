package com.ark.center.auth.infra.authentication.login.account;

import com.ark.center.auth.infra.authentication.login.provider.UserDetailsAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.authentication.login.userdetails.IamUserDetailsService;
import com.ark.center.auth.infra.authentication.token.issuer.TokenIssuer;
import com.ark.component.security.base.authentication.AuthUser;
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

    private final IamUserDetailsService iamUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";
    private volatile String userNotFoundEncodedPassword;

    public AccountLoginAuthenticationProvider(IamUserDetailsService iamUserDetailsService,
                                              TokenIssuer tokenIssuer,
                                              PasswordEncoder passwordEncoder) {
        super(tokenIssuer);
        this.iamUserDetailsService = iamUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, Authentication authentication) throws AuthenticationException {
        String presentedPassword = authentication.getCredentials().toString();
        if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
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
            AuthUser loadedUser = iamUserDetailsService.loadUserByUsername(username);
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
            this.userNotFoundEncodedPassword = this.passwordEncoder.encode(USER_NOT_FOUND_PASSWORD);
        }
    }

    private void mitigateAgainstTimingAttack(Authentication authentication) {
        if (authentication.getCredentials() != null) {
            String presentedPassword = authentication.getCredentials().toString();
            this.passwordEncoder.matches(presentedPassword, this.userNotFoundEncodedPassword);
        }
    }
}