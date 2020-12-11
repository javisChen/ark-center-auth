package com.kt.upms.service.impl;

import cn.hutool.crypto.digest.DigestUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.kt.component.catchlog.CatchAndLog;
import com.kt.component.exception.BizException;
import com.kt.upms.constants.UpmsConsts;
import com.kt.upms.entity.UpmsUser;
import com.kt.upms.mapper.UpmsUserMapper;
import com.kt.upms.service.IUpmsUserService;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 用户表 服务实现类
 * </p>
 *
 * @author
 * @since 2020-11-09
 */
@Service
@CatchAndLog
public class UpmsUserServiceImpl extends ServiceImpl<UpmsUserMapper, UpmsUser> implements IUpmsUserService {

    @Override
    @CatchAndLog
    public UpmsUser saveAndReturn(UpmsUser upmsUser) {
        String phone = upmsUser.getPhone();
        UpmsUser queryUser = this.getOne(new LambdaQueryWrapper<>(UpmsUser.class).eq(UpmsUser::getPhone, phone));
        if (queryUser != null) {
            throw new BizException("");
        }
        upmsUser.setStatus(UpmsUser.StatusEnum.NORMAL.getValue());
        upmsUser.setPassword(DigestUtil.bcrypt(phone + upmsUser.getPassword() + UpmsConsts.USER_SALT));
        this.save(upmsUser);
        upmsUser.setPassword(null);
        return upmsUser;
    }

    @Override
    public UpmsUser updateUser(UpmsUser upmsUser) {
        // 该接口禁止修改密码，修改密码用单独的接口
        upmsUser.setPassword(null);
        this.updateById(upmsUser);;
        return upmsUser;
    }

}
