package com.ark.center.auth.infra.api.converter;

import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.iam.client.api.dto.ApiDetailsDTO;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;

import java.util.List;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface ApiConverter {

    ApiMeta toAuthMeta(ApiDetailsDTO dto);

    List<ApiMeta> toAuthMeta(List<ApiDetailsDTO> dtoList);

}
