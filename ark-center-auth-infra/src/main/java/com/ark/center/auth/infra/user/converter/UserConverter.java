package com.ark.center.auth.infra.user.converter;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.AuthUserApiPermission;
import com.ark.center.iam.client.user.dto.UserApiPermissionDTO;
import com.ark.center.iam.client.user.dto.UserInnerDTO;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserConverter {

    AuthUser toAuthUser(UserInnerDTO userInnerDTO);

    AuthUserApiPermission toAuthUserApiPermission(UserApiPermissionDTO dto);

    List<AuthUserApiPermission> toAuthUserApiPermission(List<UserApiPermissionDTO> dtoList);

}
