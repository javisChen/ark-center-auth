package com.ark.center.auth.adapter.access;

import com.ark.center.auth.application.access.ApiAccessAppService;
import com.ark.center.auth.client.access.dto.ApiAccessAuthenticateDTO;
import com.ark.center.auth.client.access.query.ApiAccessAuthenticateQuery;
import com.ark.component.dto.SingleResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@Tag(name = "访问控制服务")
@RestController
@RequestMapping("/v1/access")
@RequiredArgsConstructor
public class AccessController {

    private final ApiAccessAppService apiAccessAppService;

    @Operation(summary = "API访问认证")
    @PostMapping("/api/auth")
    public SingleResponse<ApiAccessAuthenticateDTO> auth(@RequestBody ApiAccessAuthenticateQuery query) {
        return SingleResponse.ok(apiAccessAppService.authenticate(query));
    }

}