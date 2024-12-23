package com.ark.center.auth.infra.authentication.login;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(
    description = "登录响应",
    title = "登录响应结果",
    example = """
            {
              "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
            """
)
public class LoginAuthenticateResponse {

    @Schema(
        description = "访问令牌",
        requiredMode = Schema.RequiredMode.REQUIRED,
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        title = "JWT访问令牌"
    )
    private String accessToken;
}
