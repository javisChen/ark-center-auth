package com.ark.center.auth.client.verifycode.api;

import com.ark.center.auth.client.verifycode.command.GenerateVerifyCodeCommand;
import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.dto.VerifyCodeDTO;
import com.ark.component.dto.SingleResponse;
import com.ark.component.microservice.rpc.exception.FeignCommonErrorDecoder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@FeignClient(
        name = "${ark.center.auth.service.name:auth}",
        path = "/v1/verify-code",
        url = "${ark.center.auth.service.uri:}",
        dismiss404 = true,
        configuration = FeignCommonErrorDecoder.class
)
@Tag(name = "验证码服务", description = "提供验证码生成、验证等基础功能")
public interface VerifyCodeApi {
    
    @Operation(
        summary = "生成验证码",
        description = "根据不同的验证码类型和场景生成对应的验证码，支持短信、邮件、图形等类型"
    )
    @PostMapping("/generate")
    SingleResponse<VerifyCodeDTO> generate(@Validated @RequestBody GenerateVerifyCodeCommand command);
    
    @Operation(
        summary = "验证验证码",
        description = "验证用户输入的验证码是否正确，支持短信、邮件、图形等类型的验证码验证"
    )
    @PostMapping("/verify")
    SingleResponse<Boolean> verify(@Validated @RequestBody VerifyCodeCommand command);
} 