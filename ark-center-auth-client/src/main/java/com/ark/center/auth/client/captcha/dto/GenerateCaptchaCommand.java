package com.ark.center.auth.client.captcha.dto;

import com.ark.center.auth.client.captcha.CaptchaScene;
import com.ark.center.auth.client.captcha.CaptchaType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "生成验证码请求")
public class GenerateCaptchaCommand {
    
    @Schema(
        description = "验证码类型", 
        required = true, 
        example = "SMS",
        allowableValues = {
            "SMS - 短信验证码",
            "EMAIL - 邮件验证码", 
            "IMAGE - 图片验证码"
        }
    )
    @NotNull(message = "验证码类型不能为空")
    private CaptchaType type;
    
    @Schema(description = "目标对象(手机号/邮箱)", required = true, example = "13800138000")
    @NotBlank(message = "目标对象不能为空")
    private String target;
    
    @Schema(
        description = "验证码场景", 
        required = true, 
        example = "LOGIN",
        allowableValues = {
            "LOGIN - 登录验证",
            "REGISTER - 注册验证",
            "RESET_PASSWORD - 重置密码",
            "BIND_PHONE - 绑定手机",
            "UNBIND_PHONE - 解绑手机",
            "DEFAULT - 默认场景"
        }
    )
    @NotNull(message = "验证码场景不能为空")
    private CaptchaScene scene;
} 