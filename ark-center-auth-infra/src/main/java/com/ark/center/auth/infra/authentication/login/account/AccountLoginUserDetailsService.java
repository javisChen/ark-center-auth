package com.ark.center.auth.infra.authentication.login.account;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.component.security.base.user.LoginUser;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import java.util.Set;

public class AccountLoginUserDetailsService implements UserDetailsService, InitializingBean {

    private final UserGateway userGateway;
    private final UserConverter userConverter;

    public AccountLoginUserDetailsService(UserGateway userGateway,
                                          UserConverter userConverter) {
        this.userGateway = userGateway;
        this.userConverter = userConverter;
    }

    @Override
    public void afterPropertiesSet() {
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = userGateway.retrieveUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        LoginUser loginUser = userConverter.toLoginUser(user);
        loginUser.setAuthorities(Set.of(
                new SimpleGrantedAuthority("ROLE_S"),
                new SimpleGrantedAuthority("ROLE_D")));
        return loginUser;
    }

}
