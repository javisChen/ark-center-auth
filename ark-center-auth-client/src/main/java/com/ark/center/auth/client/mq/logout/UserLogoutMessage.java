package com.ark.center.auth.client.mq.logout;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class UserLogoutMessage {

    private Long userId;
    private LocalDateTime logoutTime;
}
