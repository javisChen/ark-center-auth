package com.ark.center.auth.adapter.web;

import com.ark.component.web.base.BaseController;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController extends BaseController {

    public static void main(String[] args) {
        String id = convertToUUID("649A57507B0A4432A76C097219603A8D");
//        String id = convertToUUID("9BC8D5DFDDFA4D46A9C08428B5B796FD");
        System.out.println(id);
    }

    private static String convertToUUID(String uuidStr) {
        String stringBuffer = uuidStr.substring(0, 8) + "-" +
                uuidStr.substring(8, 12) + "-" +
                uuidStr.substring(12, 16) + "-" +
                uuidStr.substring(16, 20) + "-" +
                uuidStr.substring(20);
        return stringBuffer;
    }

    @GetMapping("/admin/test")
//    @PreAuthorize("hasRole('ROLE_S')")
    public String testAdmin() {
        return "testAdmin";
    }

    @GetMapping("/test")
//    @PreAuthorize("hasRole('ROLE_DEV')")
    public Object test() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
