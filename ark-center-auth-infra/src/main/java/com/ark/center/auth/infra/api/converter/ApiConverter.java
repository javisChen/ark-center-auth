package com.ark.center.auth.infra.api.converter;

import com.ark.center.auth.domain.api.AuthApi;
import com.ark.center.iam.client.api.dto.ApiDetailsDTO;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;

import java.util.List;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface ApiConverter {

    AuthApi toAuthApi(ApiDetailsDTO dto);

    List<AuthApi> toAuthApi(List<ApiDetailsDTO> dtoList);

}
