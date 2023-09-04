
package com.ark.center.auth.infra.authentication.login;

import cn.hutool.core.util.ClassUtil;
import com.ark.center.auth.infra.authentication.token.UserToken;
import com.ark.center.auth.infra.authentication.token.generator.UserTokenGenerator;
import com.ark.component.security.base.user.LoginUser;
import com.ark.component.security.core.authentication.LoginAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

@Slf4j
public abstract class AbstractLoginAuthenticationProvider<T extends Authentication>
		implements AuthenticationProvider, InitializingBean {

	private final UserCache userCache = new NullUserCache();
	private final GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
	private final UserTokenGenerator userTokenGenerator;

	protected AbstractLoginAuthenticationProvider(UserTokenGenerator userTokenGenerator) {
		this.userTokenGenerator = userTokenGenerator;
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
        } catch (UserNotFoundException ex) {
			throw new BadCredentialsException(ex.getMessage());
		} catch (Exception ex) {
			log.error("Failed to find user", ex);
			throw new BadCredentialsException("服务器网络波动，请稍候重试");
		}
		additionalAuthenticationChecks(((LoginUser) user), authenticationToken);

		postHandle(user, authenticationToken);

		return createSuccessAuthentication(user);
	}

	protected void postHandle(UserDetails user, T authenticationToken) {

	}

	protected abstract void additionalAuthenticationChecks(LoginUser user, T authenticationToken);

	protected Authentication createSuccessAuthentication(UserDetails user) {
		LoginUser loginUser = (LoginUser) user;
		UserToken userToken = userTokenGenerator.generate(loginUser);
		return new LoginAuthenticationToken(loginUser, userToken.getTokenValue());
	}

	protected abstract UserDetails retrieveUser(T authentication) throws AuthenticationException;

	@Override
	public boolean supports(Class<?> authentication) {
		return ClassUtil.getTypeArgument(getClass()).isAssignableFrom(authentication);
	}
}
