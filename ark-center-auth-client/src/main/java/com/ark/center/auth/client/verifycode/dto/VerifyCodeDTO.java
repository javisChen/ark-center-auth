package com.ark.center.auth.client.verifycode.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(
    description = "验证码信息",
    title = "验证码返回结果"
)
public class VerifyCodeDTO {

    @Schema(
        description = "验证码ID（用于后续验证）",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "sms_1234567890",
        title = "验证码唯一标识"
    )
    private String verifyCodeId;

    @Schema(
        description = "验证码（仅在图形验证码场景下返回）",
        requiredMode = Schema.RequiredMode.NOT_REQUIRED,
        example = "123456",
        title = "验证码内容"
    )
    private String code;

    @Schema(
        description = "图形验证码的Base64编码（仅在图形验证码场景下返回）",
        requiredMode = Schema.RequiredMode.NOT_REQUIRED,
        example = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
        title = "图形验证码图片"
    )
    private String imageBase64;
} 