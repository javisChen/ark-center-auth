package com.ark.center.auth.infra.user.facade;

import com.ark.center.iam.client.user.UserQueryApi;
import com.ark.center.member.client.member.MemberCommandApi;
import com.ark.center.member.client.member.MemberQueryApi;
import com.ark.component.microservice.rpc.exception.FeignCommonErrorDecoder;
import org.springframework.cloud.openfeign.FeignClient;


@FeignClient(
        name = "${ark.center.member.service.name:product}",
        path = "/v1/members",
        url = "${ark.center.member.service.uri:}",
        dismiss404 = true
)
public interface MemberFacade extends MemberQueryApi, MemberCommandApi {

}
