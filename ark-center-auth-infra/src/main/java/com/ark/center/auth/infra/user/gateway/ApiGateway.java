package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.infra.api.ApiMeta;

import java.util.List;

public interface ApiGateway {

    List<ApiMeta> retrieveApis();
}
