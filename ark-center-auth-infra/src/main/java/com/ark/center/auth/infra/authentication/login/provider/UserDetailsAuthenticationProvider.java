package com.ark.center.auth.infra.authentication.login.provider;

import com.ark.center.auth.infra.AuthMessageSource;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.component.security.base.user.AuthUser;
import com.ark.component.security.core.token.issuer.TokenIssuer;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

@Slf4j
public abstract class UserDetailsAuthenticationProvider implements AuthenticationProvider {

    protected final Log logger = LogFactory.getLog(getClass());

    protected MessageSourceAccessor messages = AuthMessageSource.getAccessor();

    private final TokenIssuer tokenIssuer;

    @Setter
    private UserCache userCache = new NullUserCache();

    protected UserDetailsAuthenticationProvider(TokenIssuer tokenIssuer) {
        this.tokenIssuer = tokenIssuer;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        preCheckAuthentication(authentication);

        String username = authentication.getPrincipal().toString();
        boolean cacheWasUsed = true;
        AuthUser user = (AuthUser) userCache.getUserFromCache(username);
        if (user == null) {
            cacheWasUsed = false;
            try {
                user = retrieveUser(username, authentication);
            }
            catch (UserNotFoundException ex) {
                log.warn("Failed to find user '{}'", username);
                throw new BadCredentialsException(ex.getMessage());
            }
            Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
        }
        try {
            this.preCheckUser(user);
            additionalAuthenticationChecks(user, authentication);
        }
        catch (AuthenticationException ex) {
            if (!cacheWasUsed) {
                throw ex;
            }
            // There was a problem, so try again after checking
            // we're using latest data (i.e. not from the cache)
            cacheWasUsed = false;
            user = retrieveUser(username, authentication);
            this.preCheckUser(user);
            additionalAuthenticationChecks(user, authentication);
        }

        if (!cacheWasUsed) {
            userCache.putUserInCache(user);
        }
        return createSuccessAuthentication(user);
    }

    private Authentication createSuccessAuthentication(AuthUser user) {
        return tokenIssuer.issueToken(user);
    }

    protected void additionalAuthenticationChecks(UserDetails user, Authentication authentication) {

    }

    protected abstract AuthUser retrieveUser(String username, Authentication authentication);

    public void preCheckUser(UserDetails user) {
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

    protected void preCheckAuthentication(Authentication authentication) {
        logger.debug(LogMessage.format("PreAuthenticated authentication request: %s", authentication));
        if (authentication.getPrincipal() == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No pre-authenticated principal found in request.");
            }
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));

        }
        if (authentication.getCredentials() == null) {
            if (logger.isDebugEnabled()) {
                log.debug("Failed to authenticate since no credentials provided");
            }
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    }

}
