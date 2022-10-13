package com.ark.center.iam.dao.bo;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class ApiPermissionBO {

    private String permissionType;
    private String permissionCode;
    private String permissionId;
    private String apiId;
    private String apiName;
    private String apiUrl;
    private String apiMethod;
    private String apiAuthType;
}
