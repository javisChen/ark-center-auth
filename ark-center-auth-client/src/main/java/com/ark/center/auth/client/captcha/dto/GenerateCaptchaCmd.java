package com.ark.center.auth.client.captcha.dto;

import com.ark.center.auth.client.captcha.CaptchaBizType;
import com.ark.center.auth.client.captcha.CaptchaType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "生成验证码请求")
public class GenerateCaptchaCmd {
    
    @Schema(description = "验证码类型", required = true, example = "SMS")
    @NotNull(message = "验证码类型不能为空")
    private CaptchaType type;
    
    @Schema(description = "目标对象(手机号/邮箱)", required = true, example = "13800138000")
    @NotBlank(message = "目标对象不能为空")
    private String target;
    
    @Schema(description = "业务类型", required = true, example = "LOGIN")
    @NotNull(message = "业务类型不能为空")
    private CaptchaBizType bizType;
} 