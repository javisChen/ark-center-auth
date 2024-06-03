package com.ark.center.auth.infra.user.converter;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.AuthUserApiPermission;
import com.ark.center.iam.client.user.dto.UserApiPermissionDTO;
import com.ark.center.iam.client.user.dto.UserInnerDTO;
import com.ark.component.security.base.user.LoginUser;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;

import java.util.Collections;
import java.util.List;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface UserConverter {

    AuthUser toAuthUser(UserInnerDTO userInnerDTO);

    default LoginUser toLoginUser(AuthUser user) {
        LoginUser loginUser = new LoginUser();
        loginUser.setUsername(user.getUsername());
        loginUser.setPassword(user.getPassword());
        loginUser.setAccountNonExpired(true);
        loginUser.setAccountNonLocked(true);
        loginUser.setEnabled(true);
        loginUser.setCredentialsNonExpired(true);
        loginUser.setAuthorities(Collections.emptySet());
        loginUser.setUserId(user.getId());
        loginUser.setUserCode(user.getUserCode());
        loginUser.setIsSuperAdmin(user.getIsSuperAdmin());
        return loginUser;
    };

    AuthUserApiPermission toAuthUserApiPermission(UserApiPermissionDTO dto);

    List<AuthUserApiPermission> toAuthUserApiPermission(List<UserApiPermissionDTO> dtoList);

}
