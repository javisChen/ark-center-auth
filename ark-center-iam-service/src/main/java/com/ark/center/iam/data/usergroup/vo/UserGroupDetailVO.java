package com.ark.center.iam.data.usergroup.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserGroupDetailVO extends UserGroupBaseVO implements Serializable {

    private List<Long> roleIds;

}
