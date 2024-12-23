package com.ark.center.auth.adapter.captcha.web;

import com.ark.center.auth.client.captcha.command.GenerateCaptchaCommand;
import com.ark.center.auth.client.captcha.command.VerifyCaptchaCommand;
import com.ark.center.auth.client.captcha.dto.CaptchaContentDTO;
import com.ark.center.auth.captcha.CaptchaAppService;
import com.ark.component.dto.SingleResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Tag(name = "验证码服务")
@RestController
@RequestMapping("/v1/captcha")
@RequiredArgsConstructor
public class CaptchaController {
    
    private final CaptchaAppService captchaService;
    
    @Operation(summary = "生成验证码")
    @PostMapping("/generate")
    public SingleResponse<CaptchaContentDTO> generateCaptcha(
            @Parameter(description = "生成验证码请求") 
            @Validated @RequestBody GenerateCaptchaCommand command) {
        CaptchaContentDTO result = captchaService.create(command);
        result.setCode(null);
        return SingleResponse.ok(result);
    }
    
    @Operation(summary = "验证验证码")
    @PostMapping("/verify")
    public SingleResponse<Boolean> verifyCaptcha(
            @Parameter(description = "验证验证码请求")
            @Validated @RequestBody VerifyCaptchaCommand command) {
        boolean verified = captchaService.verify(command);
        return SingleResponse.ok(verified);
    }
}