package com.kt.model.dto.user;


import lombok.Data;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.List;

@Data
public class UserAddDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 用户名称
     */
    @NotBlank(message = "name 不能为空")
    private String name;

    /**
     * 手机号码
     */
    @NotBlank(message = "phone 不能为空")
    @Size(min = 11, max = 11, message = "手机号不合法")
    private String phone;

    /**
     * 用户密码
     */
    @NotBlank(message = "password 不能为空")
    private String password;

    @NotNull(message = "status 不能为空")
    @Range(min = 1, max = 2)
    private Integer status;

    public List<Long> roleIds;

    public List<Long> userGroupIds;

}
