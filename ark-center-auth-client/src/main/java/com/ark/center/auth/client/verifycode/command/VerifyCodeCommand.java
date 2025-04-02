package com.ark.center.auth.client.verifycode.command;

import com.ark.center.auth.client.verifycode.common.VerifyCodeScene;
import com.ark.center.auth.client.verifycode.common.VerifyCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
@Schema(
        description = "验证验证码请求",
        title = "验证码验证命令",
        example = """
                {
                  "type": "SMS",
                  "target": "13800138000",
                  "scene": "LOGIN",
                  "code": "123456",
                  "verifyCodeId": "sms_1234567890"
                }
                """
)
public class VerifyCodeCommand {

    @Schema(
            description = "验证码类型",
            requiredMode = Schema.RequiredMode.REQUIRED,
            example = "SMS",
            defaultValue = "SMS",
            allowableValues = {"SMS", "EMAIL", "IMAGE"},
            enumAsRef = true,
            implementation = VerifyCodeType.class,
            title = "验证码类型",
            accessMode = Schema.AccessMode.READ_WRITE
    )
    @NotNull(message = "验证码类型不能为空")
    private VerifyCodeType type;

    @Schema(
            description = "目标对象(手机号/邮箱)",
            requiredMode = Schema.RequiredMode.REQUIRED,
            example = "13800138000",
            minLength = 11,
            maxLength = 50,
            pattern = "^1[3-9]\\d{9}$|^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$",
            title = "接收验证码的目标"
    )
    @NotBlank(message = "目标对象不能为空")
    @Pattern(
            regexp = "^1[3-9]\\d{9}$|^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$",
            message = "请输入正确的手机号或邮箱"
    )
    private String target;

    @Schema(
            description = "验证码场景",
            requiredMode = Schema.RequiredMode.REQUIRED,
            example = "LOGIN",
            defaultValue = "LOGIN",
            enumAsRef = true,
            implementation = VerifyCodeScene.class,
            title = "验证码使用场景"
    )
    @NotNull(message = "验证码场景不能为空")
    private VerifyCodeScene scene;

    @Schema(
            description = "验证码",
            requiredMode = Schema.RequiredMode.REQUIRED,
            example = "123456",
            minLength = 4,
            maxLength = 6,
            pattern = "^\\d{4,6}$",
            title = "验证码内容"
    )
    @NotBlank(message = "验证码不能为空")
    @Pattern(
            regexp = "^\\d{4,6}$",
            message = "验证码格式不正确"
    )
    private String code;

    @Schema(
            description = "验证码ID（生成验证码时返回的ID）",
            requiredMode = Schema.RequiredMode.REQUIRED,
            example = "sms_1234567890",
            title = "验证码唯一标识"
    )
    @NotBlank(message = "验证码ID不能为空")
    private String verifyCodeId;
} 