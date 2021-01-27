package com.kt.upms.module.user.dto;


import com.kt.upms.validgroup.UpmsValidateGroup;
import lombok.Data;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.List;

@Data
public class UserUpdateDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotNull(groups = UpmsValidateGroup.UpdateStatus.class, message = "id 不能为空")
    private Long id;

    @NotBlank(message = "name 不能为空")
    private String name;

    @NotBlank(message = "phone 不能为空")
    @Size(min = 11, max = 11, message = "手机号不合法")
    private String phone;

    @NotBlank(message = "password 不能为空")
    private String password;

    @NotNull(message = "status 不能为空")
    @Range(min = 1, max = 2)
    private Integer status;

    public List<Long> roleIds;

    public List<Long> userGroupIds;
}
