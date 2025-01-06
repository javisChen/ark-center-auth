package com.ark.center.auth.adapter.access;

import com.ark.center.auth.application.access.ApiAccessService;
import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
import com.ark.center.auth.infra.authentication.login.LoginAuthenticateResponse;
import com.ark.center.auth.infra.authentication.login.account.AccountLoginAuthenticateRequest;
import com.ark.component.dto.ServerResponse;
import com.ark.component.dto.SingleResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.awt.desktop.QuitEvent;


@Tag(name = "访问控制服务")
@RestController
@RequestMapping("/v1/access")
@RequiredArgsConstructor
public class AccessController {

    private final ApiAccessService apiAccessService;

    @Operation(summary = "API访问认证")
    @PostMapping("/api/auth")
    public SingleResponse<Boolean> auth(@RequestBody ApiAccessAuthenticateQuery query) {
        return SingleResponse.ok(apiAccessService.authenticate(query));
    }

}