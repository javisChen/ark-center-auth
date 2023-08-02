package com.ark.center.auth.client.access;

import com.ark.center.auth.client.access.request.ApiAccessRequest;
import com.ark.center.auth.client.access.response.ApiAccessResponse;
import com.ark.component.dto.SingleResponse;
import com.ark.component.microservice.rpc.exception.FeignCommonErrorDecoder;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "${ark.center.auth.service.name:iam}",
        path = "/v1/access",
        url = "${ark.center.auth.service.uri:}",
        dismiss404 = true,
        configuration = FeignCommonErrorDecoder.class
)
public interface AccessApi {

    /**
     * API访问权限校验
     */
    @PostMapping("/api")
    SingleResponse<ApiAccessResponse> getApiAccess(@RequestBody ApiAccessRequest request);
}
