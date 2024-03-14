package com.ark.center.auth.infra.api.facade;

import com.ark.center.iam.client.api.ApiQueryApi;
import com.ark.component.microservice.rpc.exception.FeignCommonErrorDecoder;
import org.springframework.cloud.openfeign.FeignClient;


@FeignClient(
        name = "${ark.center.iam.service.name:iam}",
        path = "/v1/apis",
        url = "${ark.center.iam.service.uri:}",
        dismiss404 = true,
        configuration = FeignCommonErrorDecoder.class
)
public interface ApiFacade extends ApiQueryApi {

}
