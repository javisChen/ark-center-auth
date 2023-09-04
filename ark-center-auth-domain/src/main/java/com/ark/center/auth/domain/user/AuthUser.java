package com.ark.center.auth.domain.user;

import lombok.Data;

@Data
public class AuthUser {
    private Long id;
    private String mobile;
    private String username;
    private String userCode;
    private Boolean isSuperAdmin;
    private Integer status;
    private String password;
}
