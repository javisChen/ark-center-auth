package com.ark.center.auth.infra.authentication.login;

import com.ark.center.auth.client.login.constant.LoginMode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "基础登录请求参数")
public class BaseLoginAuthenticateRequest {

    @Schema(
        description = "登录渠道",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "APP",
        allowableValues = {"APP", "WEB", "H5", "MINI_PROGRAM"},
        title = "登录来源渠道"
    )
    @NotBlank(message = "登录渠道不能为空")
    private String channel;

    @Schema(
        description = "登录模式",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "ACCOUNT",
        implementation = LoginMode.class,
        title = "登录认证方式"
    )
    @NotNull(message = "登录模式不能为空")
    private LoginMode loginMode;

    @Schema(
        description = "设备ID",
        requiredMode = Schema.RequiredMode.NOT_REQUIRED,
        example = "A1B2C3D4E5F6",
        title = "用户设备唯一标识"
    )
    @NotBlank(message = "设备ID不能为空")
    private String deviceId;

    @Schema(
        description = "设备类型",
        example = "iPhone 13",
        title = "登录设备型号"
    )
    private String deviceType;

    @Schema(
        description = "操作系统",
        example = "iOS 15.0",
        title = "设备操作系统"
    )
    private String osVersion;

    @Schema(
        description = "应用版本",
        example = "1.0.0",
        title = "客户端版本号"
    )
    private String appVersion;

    @Schema(
        description = "登录IP",
        example = "192.168.1.1",
        title = "用户登录IP地址"
    )
    private String loginIp;
} 