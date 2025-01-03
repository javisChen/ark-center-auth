package com.ark.center.auth.infra.authentication.login.provider;

import cn.hutool.core.util.ClassUtil;
import com.ark.component.security.base.user.AuthUser;
import com.ark.component.security.core.token.issuer.TokenIssuer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

@Slf4j
public abstract class AbstractLoginAuthenticationProvider<T extends Authentication>
		implements AuthenticationProvider, InitializingBean {

	private final UserCache userCache = new NullUserCache();
	private final TokenIssuer tokenIssuer;

	protected AbstractLoginAuthenticationProvider(TokenIssuer tokenIssuer) {
		this.tokenIssuer = tokenIssuer;
	}

	protected abstract void preCheckAuthentication(T authentication) throws AuthenticationException;

	@Override
	public final void afterPropertiesSet() throws Exception {
		Assert.notNull(this.userCache, "A user cache must be set");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		log.info("User login processing, authentication = [{}]", authentication);

		@SuppressWarnings("unchecked")
		T authenticationToken = (T) authentication;

		try {
			preCheckAuthentication(authenticationToken);
		} catch (AuthenticationException e) {
			log.error("Pre check not pass, Reason = [{}]", e.getMessage());
			throw new BadCredentialsException(e.getMessage());
		}

        UserDetails user;
        try {
            user = retrieveUser(authenticationToken);
		} catch (Exception ex) {
			log.error("Failed to find user", ex);
			throw new BadCredentialsException(ex.getMessage());
		}
		additionalAuthenticationChecks(((AuthUser) user), authenticationToken);

		postHandle(user, authenticationToken);

		return issueToken(user);
	}

	protected void postHandle(UserDetails user, T authenticationToken) {

	}

	protected abstract void additionalAuthenticationChecks(AuthUser user, T authenticationToken);

	protected Authentication issueToken(UserDetails user) {
		AuthUser loginUser = (AuthUser) user;
		return tokenIssuer.issueToken(loginUser);
	}

	protected abstract UserDetails retrieveUser(T authentication) throws AuthenticationException;

	@Override
	public boolean supports(Class<?> authentication) {
		return ClassUtil.getTypeArgument(getClass()).isAssignableFrom(authentication);
	}
}
