package com.ark.center.auth.infra.authentication.login.userdetails;

import com.ark.center.auth.infra.AuthMessageSource;
import com.ark.component.security.base.user.AuthUser;
import com.ark.center.auth.infra.user.gateway.UserGateway;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class IamUserDetailsService implements UserDetailsService {

    protected MessageSourceAccessor messages = AuthMessageSource.getAccessor();

    private final UserGateway userGateway;

    @Override
    public AuthUser loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser authUser = userGateway.retrieveUserByUsername(username);
        if (authUser == null) {
            throw new UserNotFoundException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        return authUser;
    }

    public AuthUser loadUserByMobile(String mobile) throws UsernameNotFoundException {
        AuthUser authUser = userGateway.retrieveUserByMobile(mobile);
        if (authUser == null) {
            throw new UserNotFoundException(this.messages
                    .getMessage("UserDetailsAuthenticationProvider.mobileNotFound"));
        }
        return authUser;
    }
}
