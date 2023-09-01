package com.ark.center.auth.infra.authentication.login.sms;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SmsLoginAuthenticateRequest {

    @Schema(description = "手机号")
    private String mobile;

    @Schema(description = "验证码")
    private String code;

}
