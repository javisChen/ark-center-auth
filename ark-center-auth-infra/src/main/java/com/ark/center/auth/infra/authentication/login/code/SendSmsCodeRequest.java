package com.ark.center.auth.infra.authentication.login.code;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SendSmsCodeRequest {

    @Schema(description = "手机号")
    private String mobile;

}
