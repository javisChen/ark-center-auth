package com.ark.center.auth.client.captcha.dto;

import com.ark.center.auth.client.captcha.CaptchaScene;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VerifyCaptchaRequest {
    private String target;
    private String code;
    private CaptchaScene scene;
} 