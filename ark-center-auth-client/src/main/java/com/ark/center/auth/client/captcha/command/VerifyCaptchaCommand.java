package com.ark.center.auth.client.captcha.command;

import com.ark.center.auth.client.captcha.constant.CaptchaScene;
import com.ark.center.auth.client.captcha.constant.CaptchaType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(
    description = "验证验证码请求",
    title = "验证码验证命令",
    example = """
        {
          "type": "SMS",
          "target": "13800138000",
          "code": "123456",
          "scene": "LOGIN"
        }
        """
)
public class VerifyCaptchaCommand {
    
    @Schema(
        description = "验证码类型", 
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "SMS",
        enumAsRef = true,
        implementation = CaptchaType.class,
        title = "验证码类型"
    )
    @NotNull(message = "验证码类型不能为空")
    private CaptchaType type;
    
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
    private String target;
    
    @Schema(
        description = "验证码", 
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "123456",
        minLength = 6,
        maxLength = 6,
        title = "验证码内容"
    )
    @NotBlank(message = "验证码不能为空")
    private String code;
    
    @Schema(
        description = "验证码场景", 
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "LOGIN",
        enumAsRef = true,
        implementation = CaptchaScene.class,
        title = "验证码使用场景"
    )
    @NotNull(message = "验证码场景不能为空")
    private CaptchaScene scene;
} 