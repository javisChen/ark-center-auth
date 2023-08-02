package com.ark.center.auth.infra.user.facade;

import com.ark.center.iam.client.access.AccessApi;
import com.ark.component.microservice.rpc.exception.FeignCommonErrorDecoder;
import org.springframework.cloud.openfeign.FeignClient;


@FeignClient(
        name = "${ark.center.iam.service.name:iam}",
        path = "/v1/access",
        url = "${ark.center.iam.service.uri:}",
        dismiss404 = true,
        configuration = {FeignCommonErrorDecoder.class}
)
public interface PermissionFacade extends AccessApi {
}
