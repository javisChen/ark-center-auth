package com.ark.center.auth.infra.user.converter;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.iam.client.user.dto.UserInnerDTO;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserConverter {

    AuthUser toAuthUser(UserInnerDTO userInnerDTO);

}
