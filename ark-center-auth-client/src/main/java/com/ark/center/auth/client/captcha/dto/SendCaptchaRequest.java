package com.ark.center.auth.client.captcha.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SendCaptchaRequest {
    private String target;
    private String code;
} 