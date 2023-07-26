package com.ark.center.auth.adapter.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @GetMapping("/admin/test")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String testAdmin() {
        return "test";
    }
    @GetMapping("/test")
    @PreAuthorize("hasRole('ROLE_DEV')")
    public String test() {
        return "testAdmin";
    }
}
