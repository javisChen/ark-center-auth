package com.ark.center.auth.infra.authentication.login.account;

import com.ark.center.auth.infra.authentication.login.BaseLoginAuthenticateRequest;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
@Schema(
    description = "账号密码登录请求",
    title = "账号密码登录请求参数",
    example = """
            {
              "username": "admin",
              "password": "123456",
              "channel": "APP",
              "loginMode": "ACCOUNT",
              "deviceId": "A1B2C3D4E5F6",
              "deviceType": "iPhone 13",
              "osVersion": "iOS 15.0",
              "appVersion": "1.0.0"
            }
            """
)
public class AccountLoginAuthenticateRequest extends BaseLoginAuthenticateRequest {

    @Schema(
        description = "用户名",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "admin",
        minLength = 4,
        maxLength = 32,
        pattern = "^[a-zA-Z0-9_-]{4,32}$",
        title = "登录用户名"
    )
    @NotBlank(message = "用户名不能为空")
    @Pattern(regexp = "^[a-zA-Z0-9_-]{4,32}$", message = "用户名格式不正确")
    private String username;

    @Schema(
        description = "密码",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "123456",
        minLength = 6,
        maxLength = 32,
        title = "登录密码"
    )
    @NotBlank(message = "密码不能为空")
    private String password;
}
