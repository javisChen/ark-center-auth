package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.infra.user.converter.MemberConverter;
import com.ark.center.auth.infra.user.facade.MemberFacade;
import com.ark.center.member.client.member.command.MemberRegisterCommand;
import com.ark.center.member.client.member.common.RegisterType;
import com.ark.center.member.client.member.dto.MemberAuthDTO;
import com.ark.center.member.client.member.dto.MemberRegisterDTO;
import com.ark.component.microservice.rpc.util.RpcUtils;
import com.ark.component.security.base.authentication.AuthUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;



/**
 * 用户远程服务调用实现
 */
@Component
@RequiredArgsConstructor
public class MemberGatewayImpl implements MemberGateway {

    private final MemberFacade memberFacade;
    private final MemberConverter memberConverter;

    @Override
    public AuthUser retrieveUserByMobile(String mobile) {
        MemberAuthDTO userAuthDTO = RpcUtils.checkAndGetData(memberFacade.getMemberAuthInfo(mobile));
        if (userAuthDTO == null) {
            return null;
        }
        return memberConverter.toAuthUser(userAuthDTO);
    }

    @Override
    public AuthUser retrieveUserByUsername(String username) {
        MemberAuthDTO userAuthDTO = RpcUtils.checkAndGetData(memberFacade.getMemberAuthInfo(username));
        if (userAuthDTO == null) {
            return null;
        }
        return memberConverter.toAuthUser(userAuthDTO);
    }

    @Override
    public AuthUser register(String mobile) {
        MemberRegisterCommand memberRegisterCommand = new MemberRegisterCommand();
        memberRegisterCommand.setRegisterType(RegisterType.MOBILE);
        memberRegisterCommand.setMobile(mobile);
        memberRegisterCommand.setRegisterChannel("MALL_APP");
        MemberRegisterDTO memberRegisterDTO = RpcUtils.checkAndGetData(memberFacade.register(memberRegisterCommand));
        return memberConverter.toAuthUser(memberRegisterDTO);
    }

}
