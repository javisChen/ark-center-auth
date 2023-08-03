package com.ark.center.auth.client.access.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
@AllArgsConstructor
@Builder
public class ApiAccessResponse {

    private Integer code;

    public static ApiAccessResponse fail(int code) {
        return ApiAccessResponse.builder()
                .code(code)
                .build();
    }

    public static ApiAccessResponse success() {
        return success(null);
    }
    public static ApiAccessResponse success(UserResponse userResponse) {
        return ApiAccessResponse.builder()
                .code(HttpStatus.OK.value())
                .build();
    }

}
