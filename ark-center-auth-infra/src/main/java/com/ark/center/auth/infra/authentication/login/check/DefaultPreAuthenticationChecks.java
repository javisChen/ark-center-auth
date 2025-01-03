package com.ark.center.auth.infra.authentication.login.check;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

@Slf4j
public class DefaultPreAuthenticationChecks implements UserDetailsChecker {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Override
    public void check(UserDetails user) {
        if (!user.isAccountNonLocked()) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate since user account is locked");
            }
            throw new LockedException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"));

        }
        if (!user.isEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate since user account is disabled");
            }
            throw new DisabledException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
        }
        if (!user.isAccountNonExpired()) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate since user account has expired");
            }
            throw new AccountExpiredException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
        }
    }

}