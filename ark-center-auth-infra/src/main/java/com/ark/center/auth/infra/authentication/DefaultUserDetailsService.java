package com.ark.center.auth.infra.authentication;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.Collections;

public class DefaultUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = new User("jc", "$2a$10$r3l66yYouxHT7l2TUR.7CO48i6rVXaZ489fDGGe88DK8EkbfxQiyS", Collections.emptyList());
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return new User(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(),
                user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
    }

    public static void main(String[] args) {
        String gensalt = BCrypt.gensalt();
        System.out.println("salt：" + gensalt);
        String hashpw = BCrypt.hashpw("123", gensalt);
        System.out.println("hash：" + hashpw);
    }
}
