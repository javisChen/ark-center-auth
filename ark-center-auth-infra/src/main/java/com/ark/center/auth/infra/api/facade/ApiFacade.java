package com.ark.center.auth.infra.api.facade;

import com.ark.center.iam.client.api.ApiQryApi;
import com.ark.component.microservice.rpc.exception.FeignCommonErrorDecoder;
import org.springframework.cloud.openfeign.FeignClient;


@FeignClient(
        name = "${ark.center.iam.service.name:iam}",
        path = "/v1/inner/apis",
        url = "${ark.center.iam.service.uri:}",
        dismiss404 = true,
        configuration = {FeignCommonErrorDecoder.class}
)
public interface ApiFacade extends ApiQryApi {

}
