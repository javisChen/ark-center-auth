package com.ark.center.auth.adapter.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @GetMapping("/admin/test")
    @PreAuthorize("hasAnyAuthority('ROLE_D')")
    public String testAdmin() {
        return "testAdmin";
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ROLE_DEV')")
    public Object test() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
