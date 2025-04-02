package com.ark.center.auth.infra.authentication.login.userdetails;

import ch.qos.logback.core.joran.action.PreconditionValidator;
import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.infra.authentication.LoginAuthenticationDetails;
import com.ark.center.auth.infra.support.AuthMessageSource;
import com.ark.component.security.base.authentication.AuthUser;
import com.ark.center.auth.infra.user.gateway.UserSourceProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 默认认证用户服务实现
 */
@RequiredArgsConstructor
@Service
public class DefaultAuthenticationUserService implements AuthenticationUserService {

    protected MessageSourceAccessor messages = AuthMessageSource.getAccessor();

    private final List<UserSourceProvider> userSourceProviders;

    @Override
    public AuthUser loadUserByUsername(String username, Authentication authentication) {
        AppCode appCode = getAppCode(authentication);
        UserSourceProvider provider = getUserSourceProvider(appCode);
        AuthUser authUser = provider.retrieveUserByUsername(username, authentication);
        if (authUser == null) {
            throw new UserNotFoundException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        return authUser;
    }

    @Override
    public AuthUser loadUserByMobile(String mobile, Authentication authentication) {
        AppCode appCode = getAppCode(authentication);
        UserSourceProvider provider = getUserSourceProvider(appCode);
        AuthUser authUser = provider.retrieveUserByMobile(mobile, authentication);
        if (authUser == null) {
            throw new UserNotFoundException(this.messages
                    .getMessage("UserDetailsAuthenticationProvider.mobileNotFound"));
        }
        return authUser;
    }

    private UserSourceProvider getUserSourceProvider(AppCode appCode) {
        return userSourceProviders.stream()
                .filter(provider -> provider.supports(appCode))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No user source provider found for app: " + appCode));
    }

    private AppCode getAppCode(Authentication authentication) {
        if (authentication != null && authentication.getDetails() instanceof LoginAuthenticationDetails details) {
            return details.getBaseLoginAuthenticateRequest().getAppCode();
        }
        throw new IllegalStateException("No application code found in authentication details");
    }
} 