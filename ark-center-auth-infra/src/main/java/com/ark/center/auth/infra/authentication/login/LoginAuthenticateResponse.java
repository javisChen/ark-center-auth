package com.ark.center.auth.infra.authentication.login;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginAuthenticateResponse {

    private String accessToken;

}
