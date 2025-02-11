package com.ark.center.auth.client.authentication.command;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Schema(
    description = "手机验证码登录请求",
    title = "手机验证码登录请求参数",
    example = """
            {
              "mobile": "13800138000",
              "captcha": "123456",
              "appCode": "MALL_APP",
              "clientType": "IOS",
              "authStrategy": "SMS",
              "deviceId": "A1B2C3D4E5F6",
              "deviceType": "iPhone 13",
              "osVersion": "iOS 15.0",
              "appVersion": "1.0.0"
            }
            """
)
public class MobileLoginAuthenticateRequest extends BaseLoginAuthenticateRequest {

    @Schema(
        description = "手机号",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "13800138000",
        title = "登录手机号"
    )
    @NotBlank(message = "手机号不能为空")
    private String mobile;

    @Schema(
        description = "验证码",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "123456",
        title = "短信验证码"
    )
    @NotBlank(message = "验证码不能为空")
    private String captcha;
}
