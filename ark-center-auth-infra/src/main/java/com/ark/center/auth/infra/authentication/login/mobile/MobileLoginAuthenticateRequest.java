package com.ark.center.auth.infra.authentication.login.mobile;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class MobileLoginAuthenticateRequest {

    @Schema(description = "手机号")
    private String mobile;

    @Schema(description = "验证码")
    private String captcha;

}
