package com.ark.center.auth.client.authentication.command;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.client.authentication.common.AuthStrategy;
import com.ark.center.auth.client.authentication.common.ClientType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

/**
 * 基础登录认证请求
 */
@Data
@Schema(description = "基础登录请求参数")
public class BaseLoginAuthenticateRequest {

    @Schema(
        description = "应用编码",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "MALL_APP",
        implementation = AppCode.class,
        title = "应用编码"
    )
    @NotNull(message = "应用编码不能为空")
    private AppCode appCode;

    @Schema(
        description = "客户端类型",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "IOS",
        implementation = ClientType.class,
        title = "登录客户端类型"
    )
    @NotNull(message = "客户端类型不能为空")
    private ClientType clientType;

    @Schema(
        description = "认证策略",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "PWD",
        implementation = AuthStrategy.class,
        title = "登录认证策略"
    )
    @NotNull(message = "认证策略不能为空")
    private AuthStrategy authStrategy;

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

    @Schema(
            description = "验证码ID（用于后续验证）",
            requiredMode = Schema.RequiredMode.NOT_REQUIRED,
            example = "sms_1234567890",
            title = "验证码唯一标识"
    )
    @NotBlank(message = "验证码ID不能为空")
    private String verifyCodeId;

} 