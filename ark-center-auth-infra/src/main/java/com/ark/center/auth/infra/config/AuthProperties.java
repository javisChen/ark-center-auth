package com.ark.center.auth.infra.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * 认证配置，支持Nacos动态热更新
 *
 * @author Javis
 */
@ConfigurationProperties(prefix = "ark.center.auth")
@Data
@Configuration
@RefreshScope
public class AuthProperties {

    /**
     * 放行名单
     */
    private List<String> allowList = new ArrayList<>();

    /**
     * 禁止名单
     */
    private List<String> blockList = new ArrayList<>();
}
