package com.kt.cloud.iam.data.user.vo;


import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data
public class UserPageListVO extends UserBaseVO {

    private List<String> roles;
    private List<String> userGroups;
}
