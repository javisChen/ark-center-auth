package com.ark.center.auth.infra.api.converter;

import com.ark.center.auth.domain.api.AuthApi;
import com.ark.center.iam.model.api.dto.ApiDetailsDTO;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface ApiConverter {

    AuthApi toAuthApi(ApiDetailsDTO dto);
    List<AuthApi> toAuthApi(List<ApiDetailsDTO> dtoList);

}
