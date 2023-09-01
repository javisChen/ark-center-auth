package com.ark.center.auth.infra.authentication.login.sms;

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

public class SmsLoginUserDetailsService implements UserDetailsService, InitializingBean {

    private final UserGateway userGateway;
    private final UserConverter userConverter;

    public SmsLoginUserDetailsService(UserGateway userGateway,
                                      UserConverter userConverter) {
        this.userGateway = userGateway;
        this.userConverter = userConverter;
    }

    @Override
    public void afterPropertiesSet() {
    }

    @Override
    public UserDetails loadUserByUsername(String mobile) throws UsernameNotFoundException {
        AuthUser user = userGateway.retrieveUserByMobile(mobile);
        if (user == null) {
            throw new MobileNotFoundException(mobile);
        }
        LoginUser loginUser = userConverter.toLoginUser(user);
        loginUser.setAuthorities(Set.of(
                new SimpleGrantedAuthority("ROLE_S"),
                new SimpleGrantedAuthority("ROLE_D")));
        return loginUser;
    }


}
