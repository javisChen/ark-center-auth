package com.ark.center.auth.infra.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * 安全配置
 *
 * @author Javis
 */
@ConfigurationProperties(prefix = "ark.auth")
@Data
@Configuration
public class SecurityCoreProperties {

    /**
     * 放行名单
     */
    private List<String> allowList = new ArrayList<>();

    /**
     * 禁止名单
     */
    private List<String> blockList = new ArrayList<>();
}
