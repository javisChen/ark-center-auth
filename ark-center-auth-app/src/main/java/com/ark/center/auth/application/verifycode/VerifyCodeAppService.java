package com.ark.center.auth.application.verifycode;

import com.ark.center.auth.client.verifycode.common.VerifyCodeType;
import com.ark.center.auth.client.verifycode.command.GenerateVerifyCodeCommand;
import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.dto.VerifyCodeDTO;
import com.ark.center.auth.infra.verifycode.VerifyCodeProvider;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 验证码应用服务
 */
@Service
public class VerifyCodeAppService {
    
    private final Map<VerifyCodeType, VerifyCodeProvider> providerMap;

    public VerifyCodeAppService(List<VerifyCodeProvider> providers) {
        this.providerMap = providers.stream()
                .collect(Collectors.toMap(
                        VerifyCodeProvider::getProviderType,
                        Function.identity()
                ));
    }
    
    /**
     * 创建验证码
     */
    public VerifyCodeDTO create(GenerateVerifyCodeCommand command) {
        return getProvider(command.getType()).generate(command);
    }
    
    /**
     * 验证验证码
     */
    public boolean verify(VerifyCodeCommand command) {
        return getProvider(command.getType()).verify(command);
    }
    
    /**
     * 获取验证码提供者
     */
    private VerifyCodeProvider getProvider(VerifyCodeType type) {
        VerifyCodeProvider provider = providerMap.get(type);
        if (provider == null) {
            throw new IllegalArgumentException("Unsupported verify code type: " + type);
        }
        return provider;
    }
} 