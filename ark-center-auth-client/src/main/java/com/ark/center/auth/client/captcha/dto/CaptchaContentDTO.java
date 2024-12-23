package com.ark.center.auth.client.captcha.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
@Schema(
    description = "验证码生成结果",
    example = """
        {
          "code": "123456",
          "expireAt": 1648888888888,
          "expireTime": "2024-03-02T15:34:48"
        }
        """
)
public class CaptchaContentDTO {
    
    @Schema(
        description = "验证码", 
        example = "123456",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String code;
    
    @Schema(
        description = "过期时间戳(毫秒)", 
        example = "1648888888888",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    private Long expireAt;
    
    @Schema(
        description = "过期时间", 
        example = "2024-03-02T15:34:48",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    private LocalDateTime expireTime;
}