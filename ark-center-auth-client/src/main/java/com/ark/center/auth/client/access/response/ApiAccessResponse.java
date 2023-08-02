package com.ark.center.auth.client.access.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class ApiAccessResponse {

    private UserResponse userResponse;
    private Boolean result = false;

    public static ApiAccessResponse success() {
        return success(true);
    }

    public static ApiAccessResponse success(boolean result) {
        return ApiAccessResponse.builder()
                .result(result)
                .build();
    }

    public static ApiAccessResponse success(UserResponse userResponse) {
        return ApiAccessResponse.builder()
                .result(true)
                .userResponse(userResponse)
                .build();
    }

}
