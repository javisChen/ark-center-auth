package com.ark.center.auth.infra.user.converter;

import com.ark.component.security.base.user.AuthUser;
import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.iam.client.user.dto.UserApiPermissionDTO;
import com.ark.center.iam.client.user.dto.UserAuthDTO;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;

import java.util.List;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface UserConverter {

    @Mapping(target = "userId", source = "id")
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "credentialsNonExpired", ignore = true)
    @Mapping(target = "authorities", ignore = true)
    @Mapping(target = "accountNonLocked", ignore = true)
    @Mapping(target = "accountNonExpired", ignore = true)
    AuthUser toAuthUser(UserAuthDTO userAuthDTO);

    AuthUserApiPermission toAuthUserApiPermission(UserApiPermissionDTO dto);

    List<AuthUserApiPermission> toAuthUserApiPermission(List<UserApiPermissionDTO> dtoList);

}
