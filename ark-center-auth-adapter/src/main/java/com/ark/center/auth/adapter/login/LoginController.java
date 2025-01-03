package com.ark.center.auth.adapter.login;

import com.ark.center.auth.infra.authentication.login.LoginAuthenticateResponse;
import com.ark.center.auth.infra.authentication.login.account.AccountLoginAuthenticateRequest;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 仅仅作为Swagger扫描用的
 */
@Tag(name = "认证服务")
@RestController
@RequestMapping("/v1")
public class LoginController {

    @Operation(summary = "账号密码登录")
    @PostMapping("/login")
    public SingleResponse<LoginAuthenticateResponse> login(
            @RequestBody AccountLoginAuthenticateRequest request) {
        return SingleResponse.ok(new LoginAuthenticateResponse("")); // 仅用于文档展示
    }

    @Operation(summary = "登出")
    @PostMapping("/logout")
    public ServerResponse logout() {
        return ServerResponse.ok(); // 仅用于文档展示
    }
} 