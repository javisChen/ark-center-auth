package com.ark.center.auth.infra.authentication.login.check;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

@Slf4j
public class DefaultPostAuthenticationChecks implements UserDetailsChecker {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Override
    public void check(UserDetails user) {
        if (!user.isCredentialsNonExpired()) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate since user account credentials have expired");
            }
            throw new CredentialsExpiredException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.credentialsExpired",
                            "User credentials have expired"));
        }
    }

}