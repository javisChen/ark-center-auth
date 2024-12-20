package com.ark.center.auth.client.captcha;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(description = "验证码生成结果")
public class CaptchaResult {
    
    @Schema(description = "验证码")
    private String code;
    
    @Schema(description = "过期时间(时间戳)")
    private Long expireTime;
    
    @Schema(description = "是否成功")
    private boolean success;
}