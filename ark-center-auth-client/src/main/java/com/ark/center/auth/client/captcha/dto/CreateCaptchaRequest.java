package com.ark.center.auth.client.captcha.dto;

import com.ark.center.auth.client.captcha.CaptchaScene;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CreateCaptchaRequest {
    private String target;
    private CaptchaScene scene;
} 