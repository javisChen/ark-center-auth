package com.ark.center.auth.domain.user.gateway;

import com.ark.center.auth.domain.api.AuthApi;

import java.util.List;

public interface ApiGateway {

    List<AuthApi> retrieveApis();
}
