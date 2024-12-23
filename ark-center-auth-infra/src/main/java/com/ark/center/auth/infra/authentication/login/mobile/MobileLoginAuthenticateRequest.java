package com.ark.center.auth.infra.authentication.login.mobile;

import com.ark.center.auth.infra.authentication.login.BaseLoginAuthenticateRequest;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(
    description = "手机验证码登录请求",
    title = "手机验证码登录请求参数",
    example = """
            {
              "mobile": "13800138000",
              "captcha": "123456",
              "channel": "APP",
              "loginMode": "MOBILE",
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
        minLength = 11,
        maxLength = 11,
        pattern = "^1[3-9]\\d{9}$",
        title = "登录手机号"
    )
    @NotBlank(message = "手机号不能为空")
    @Pattern(regexp = "^1[3-9]\\d{9}$", message = "请输入正确的手机号")
    private String mobile;

    @Schema(
        description = "验证码",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "123456",
        minLength = 6,
        maxLength = 6,
        pattern = "^\\d{6}$",
        title = "短信验证码"
    )
    @NotBlank(message = "验证码不能为空")
    @Pattern(regexp = "^\\d{6}$", message = "请输入6位数字验证码")
    private String captcha;
}
