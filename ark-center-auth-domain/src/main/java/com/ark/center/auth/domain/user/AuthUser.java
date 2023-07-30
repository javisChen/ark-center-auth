package com.ark.center.auth.domain.user;

import lombok.Data;

@Data
public class AuthUser {

    private Long id;
    private String phone;
    private String userName;
    private String password;
    private Integer status;

}
