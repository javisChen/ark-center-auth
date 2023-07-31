package com.ark.center.auth.infra.authentication.login.token.cache;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserCacheInfo {

    private String accessToken;
    private Integer expires;
}
