package com.ark.center.auth.adapter.verifycode.web;

import com.ark.center.auth.application.verifycode.VerifyCodeAppService;
import com.ark.center.auth.client.verifycode.api.VerifyCodeApi;
import com.ark.center.auth.client.verifycode.command.GenerateVerifyCodeCommand;
import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.dto.VerifyCodeDTO;
import com.ark.component.dto.SingleResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 验证码控制器
 */
@RestController
@RequestMapping("/v1/verify-code")
@RequiredArgsConstructor
public class VerifyCodeController implements VerifyCodeApi {
    
    private final VerifyCodeAppService verifyCodeAppService;

    @Override
    public SingleResponse<VerifyCodeDTO> generate(@Validated @RequestBody GenerateVerifyCodeCommand command) {
        VerifyCodeDTO result = verifyCodeAppService.create(command);
        return SingleResponse.ok(result);
    }

    @Override
    public SingleResponse<Boolean> verify(@Validated @RequestBody VerifyCodeCommand command) {
        boolean verified = verifyCodeAppService.verify(command);
        return SingleResponse.ok(verified);
    }
} 