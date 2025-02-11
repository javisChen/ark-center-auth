package com.ark.center.auth.infra.user;

import lombok.Data;

@Data
public class AuthUserApiPermission {
    /**
     * API ID
     */
    private Long apiId;

    private String uri;

    private String method;

}
