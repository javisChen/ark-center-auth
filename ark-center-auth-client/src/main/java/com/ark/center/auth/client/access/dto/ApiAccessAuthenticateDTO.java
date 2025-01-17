package com.ark.center.auth.client.access.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * API访问认证响应
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "API访问认证响应")
public class ApiAccessAuthenticateDTO {

    @Schema(description = "是否允许访问")
    private Boolean allowed;

    @Schema(description = "拒绝原因，当allowed为false时返回")
    private String denyReason;

    /**
     * 创建允许访问的响应
     */
    public static ApiAccessAuthenticateDTO allowed() {
        return ApiAccessAuthenticateDTO.builder()
                .allowed(true)
                .build();
    }

    /**
     * 创建拒绝访问的响应
     */
    public static ApiAccessAuthenticateDTO denied(String reason) {
        return ApiAccessAuthenticateDTO.builder()
                .allowed(false)
                .denyReason(reason)
                .build();
    }
} 