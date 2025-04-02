package com.ark.center.auth.infra.user.converter;

import com.ark.center.member.client.member.common.MemberStatus;
import com.ark.center.member.client.member.dto.MemberAuthDTO;
import com.ark.center.member.client.member.dto.MemberRegisterDTO;
import com.ark.component.security.base.authentication.AuthUser;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface MemberConverter {

    default AuthUser toAuthUser(MemberAuthDTO memberAuthDTO) {
        AuthUser authUser = new AuthUser();
        authUser.setUserId(memberAuthDTO.getMemberId());
        authUser.setUserCode(memberAuthDTO.getMemberNo());
        authUser.setPassword(memberAuthDTO.getPassword());
        authUser.setUsername(memberAuthDTO.getNickname());
        authUser.setAccountNonExpired(memberAuthDTO.getStatus() == MemberStatus.ENABLED);
        authUser.setAccountNonLocked(memberAuthDTO.getStatus() == MemberStatus.ENABLED);
        authUser.setCredentialsNonExpired(memberAuthDTO.getStatus() == MemberStatus.ENABLED);
        authUser.setEnabled(memberAuthDTO.getStatus() == MemberStatus.ENABLED);
        return authUser;
    }

    default AuthUser toAuthUser(MemberRegisterDTO memberRegisterDTO) {
        AuthUser authUser = new AuthUser();
        authUser.setUserId(memberRegisterDTO.getMemberId());
        authUser.setUserCode(memberRegisterDTO.getMemberNo());
        authUser.setAccountNonExpired(true);
        authUser.setAccountNonLocked(true);
        authUser.setCredentialsNonExpired(true);
        authUser.setEnabled(true);
        return authUser;
    }
}
