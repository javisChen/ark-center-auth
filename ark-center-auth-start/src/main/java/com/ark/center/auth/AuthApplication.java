package com.ark.center.auth;

import com.ark.component.web.config.ArkWebConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication(scanBasePackages = {"com.ark.center.auth"})
@EnableFeignClients
@EnableDiscoveryClient
public class AuthApplication extends ArkWebConfig {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

}