package com.ark.center.auth.infra.authentication.login.account;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AccountLoginAuthenticateRequest {

    @Schema(description = "用户名")
    private String username;

    @Schema(description = "密码")
    private String password;

    private String code;

}
