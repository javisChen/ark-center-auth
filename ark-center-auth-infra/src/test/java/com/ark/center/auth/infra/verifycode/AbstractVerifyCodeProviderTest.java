package com.ark.center.auth.infra.verifycode;

import com.ark.center.auth.client.verifycode.common.VerifyCodeScene;
import com.ark.center.auth.client.verifycode.common.VerifyCodeType;
import com.ark.center.auth.client.verifycode.command.GenerateVerifyCodeCommand;
import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.dto.VerifyCodeDTO;
import com.ark.component.cache.CacheService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class AbstractVerifyCodeProviderTest {

    private CacheService cacheService;
    private TestVerifyCodeProvider verifyCodeProvider;
    private static final String TEST_TARGET = "13800138000";
    private static final String TEST_CODE = "123456";

    @BeforeEach
    void setUp() {
        cacheService = Mockito.mock(CacheService.class);
        verifyCodeProvider = new TestVerifyCodeProvider(cacheService);
    }

    @Test
    void generate_shouldGenerateAndSaveVerifyCode() {
        // Arrange
        when(cacheService.setIfAbsent(anyString(), any(), anyLong(), any())).thenReturn(true);
        GenerateVerifyCodeCommand command = new GenerateVerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setScene(VerifyCodeScene.LOGIN);
        command.setTarget(TEST_TARGET);

        // Act
        VerifyCodeDTO result = verifyCodeProvider.generate(command);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getVerifyCodeId());
        assertTrue(result.getVerifyCodeId().startsWith("sms_"));

        // Verify cache interactions
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<AbstractVerifyCodeProvider.VerifyCodeCacheItem> itemCaptor = 
            ArgumentCaptor.forClass(AbstractVerifyCodeProvider.VerifyCodeCacheItem.class);
        verify(cacheService).setIfAbsent(
            keyCaptor.capture(), 
            itemCaptor.capture(), 
            eq(2L), 
            eq(TimeUnit.MINUTES)
        );

        AbstractVerifyCodeProvider.VerifyCodeCacheItem savedItem = itemCaptor.getValue();
        assertEquals(TEST_CODE, savedItem.getCode());
        assertEquals(TEST_TARGET, savedItem.getTarget());
        assertEquals(VerifyCodeScene.LOGIN, savedItem.getScene());
        assertEquals(VerifyCodeType.SMS, savedItem.getType());
        assertNotNull(savedItem.getCreateTime());
    }

    @Test
    void verify_shouldReturnTrueForValidCode() {
        // Arrange
        String verifyCodeId = "sms_test_123";
        AbstractVerifyCodeProvider.VerifyCodeCacheItem cacheItem = new AbstractVerifyCodeProvider.VerifyCodeCacheItem();
        cacheItem.setCode(TEST_CODE);
        cacheItem.setTarget(TEST_TARGET);
        cacheItem.setScene(VerifyCodeScene.LOGIN);
        cacheItem.setType(VerifyCodeType.SMS);
        cacheItem.setCreateTime(System.currentTimeMillis());

        when(cacheService.get(anyString(), eq(AbstractVerifyCodeProvider.VerifyCodeCacheItem.class)))
            .thenReturn(cacheItem);

        VerifyCodeCommand command = new VerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setScene(VerifyCodeScene.LOGIN);
        command.setTarget(TEST_TARGET);
        command.setCode(TEST_CODE);
        command.setVerifyCodeId(verifyCodeId);

        // Act
        boolean result = verifyCodeProvider.verify(command);

        // Assert
        assertTrue(result);
        verify(cacheService, times(2)).del(anyString()); // Both verify code and fail count should be deleted
    }

    @Test
    void verify_shouldReturnFalseForInvalidCode() {
        // Arrange
        String verifyCodeId = "sms_test_123";
        AbstractVerifyCodeProvider.VerifyCodeCacheItem cacheItem = new AbstractVerifyCodeProvider.VerifyCodeCacheItem();
        cacheItem.setCode(TEST_CODE);
        cacheItem.setTarget(TEST_TARGET);
        cacheItem.setScene(VerifyCodeScene.LOGIN);
        cacheItem.setType(VerifyCodeType.SMS);
        cacheItem.setCreateTime(System.currentTimeMillis());

        when(cacheService.get(anyString(), eq(AbstractVerifyCodeProvider.VerifyCodeCacheItem.class)))
            .thenReturn(cacheItem);
        when(cacheService.incrBy(anyString(), eq(1L))).thenReturn(1L);

        VerifyCodeCommand command = new VerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setScene(VerifyCodeScene.LOGIN);
        command.setTarget(TEST_TARGET);
        command.setCode("wrong_code");
        command.setVerifyCodeId(verifyCodeId);

        // Act
        boolean result = verifyCodeProvider.verify(command);

        // Assert
        assertFalse(result);
        verify(cacheService, never()).del(anyString()); // Verify code should not be deleted for failed verification
        verify(cacheService).incrBy(anyString(), eq(1L)); // Failure count should be incremented
        verify(cacheService).setIfAbsent(anyString(), eq(1L), eq(2L), eq(TimeUnit.MINUTES)); // Failure count should be saved with expiration
    }

    @Test
    void verify_shouldClearCodeAfterMaxFailures() {
        // Arrange
        String verifyCodeId = "sms_test_123";
        AbstractVerifyCodeProvider.VerifyCodeCacheItem cacheItem = new AbstractVerifyCodeProvider.VerifyCodeCacheItem();
        cacheItem.setCode(TEST_CODE);
        cacheItem.setTarget(TEST_TARGET);
        cacheItem.setScene(VerifyCodeScene.LOGIN);
        cacheItem.setType(VerifyCodeType.SMS);
        cacheItem.setCreateTime(System.currentTimeMillis());

        when(cacheService.get(anyString(), eq(AbstractVerifyCodeProvider.VerifyCodeCacheItem.class)))
            .thenReturn(cacheItem);
        when(cacheService.incrBy(anyString(), eq(1L))).thenReturn(3L); // Max failures reached

        VerifyCodeCommand command = new VerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setScene(VerifyCodeScene.LOGIN);
        command.setTarget(TEST_TARGET);
        command.setCode("wrong_code");
        command.setVerifyCodeId(verifyCodeId);

        // Act
        boolean result = verifyCodeProvider.verify(command);

        // Assert
        assertFalse(result);
        verify(cacheService, times(2)).del(anyString()); // Both verify code and fail count should be deleted
        verify(cacheService).setIfAbsent(anyString(), eq(3L), eq(2L), eq(TimeUnit.MINUTES)); // Failure count should be saved with expiration
    }

    @Test
    void verify_shouldReturnFalseForTypeMismatch() {
        // Arrange
        String verifyCodeId = "sms_test_123";
        AbstractVerifyCodeProvider.VerifyCodeCacheItem cacheItem = new AbstractVerifyCodeProvider.VerifyCodeCacheItem();
        cacheItem.setCode(TEST_CODE);
        cacheItem.setTarget(TEST_TARGET);
        cacheItem.setScene(VerifyCodeScene.LOGIN);
        cacheItem.setType(VerifyCodeType.EMAIL); // Different type
        cacheItem.setCreateTime(System.currentTimeMillis());

        when(cacheService.get(anyString(), eq(AbstractVerifyCodeProvider.VerifyCodeCacheItem.class)))
            .thenReturn(cacheItem);

        VerifyCodeCommand command = new VerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setScene(VerifyCodeScene.LOGIN);
        command.setTarget(TEST_TARGET);
        command.setCode(TEST_CODE);
        command.setVerifyCodeId(verifyCodeId);

        // Act
        boolean result = verifyCodeProvider.verify(command);

        // Assert
        assertFalse(result);
        verify(cacheService, never()).del(anyString());
        verify(cacheService, never()).incrBy(anyString(), anyLong());
    }

    @Test
    void verify_shouldReturnFalseForSceneMismatch() {
        // Arrange
        String verifyCodeId = "sms_test_123";
        AbstractVerifyCodeProvider.VerifyCodeCacheItem cacheItem = new AbstractVerifyCodeProvider.VerifyCodeCacheItem();
        cacheItem.setCode(TEST_CODE);
        cacheItem.setTarget(TEST_TARGET);
        cacheItem.setScene(VerifyCodeScene.REGISTER); // Different scene
        cacheItem.setType(VerifyCodeType.SMS);
        cacheItem.setCreateTime(System.currentTimeMillis());

        when(cacheService.get(anyString(), eq(AbstractVerifyCodeProvider.VerifyCodeCacheItem.class)))
            .thenReturn(cacheItem);

        VerifyCodeCommand command = new VerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setScene(VerifyCodeScene.LOGIN);
        command.setTarget(TEST_TARGET);
        command.setCode(TEST_CODE);
        command.setVerifyCodeId(verifyCodeId);

        // Act
        boolean result = verifyCodeProvider.verify(command);

        // Assert
        assertFalse(result);
        verify(cacheService, never()).del(anyString());
        verify(cacheService, never()).incrBy(anyString(), anyLong());
    }

    private static class TestVerifyCodeProvider extends AbstractVerifyCodeProvider {
        public TestVerifyCodeProvider(CacheService cacheService) {
            super(cacheService);
        }

        @Override
        protected String generateCode() {
            return TEST_CODE;
        }

        @Override
        public VerifyCodeType getProviderType() {
            return VerifyCodeType.SMS;
        }

        @Override
        public void send(String target, String code) {
            // Do nothing for test
        }
    }
} 