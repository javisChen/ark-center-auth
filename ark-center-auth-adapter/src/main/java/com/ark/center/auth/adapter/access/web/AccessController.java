package com.ark.center.auth.adapter.access.web;

import com.ark.center.auth.application.access.AccessAppService;
import com.ark.center.auth.client.access.AccessApi;
import com.ark.center.auth.client.access.request.ApiAccessRequest;
import com.ark.center.auth.client.access.response.ApiAccessResponse;
import com.ark.component.dto.SingleResponse;
import com.ark.component.web.base.BaseController;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/access")
@RequiredArgsConstructor
public class AccessController extends BaseController implements AccessApi {

    private final AccessAppService accessAppService;

    @Override
    public SingleResponse<ApiAccessResponse> getApiAccess(ApiAccessRequest request) {
        return SingleResponse.ok(accessAppService.getApiAccess(request));
    }
}
